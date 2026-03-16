"""detection/exposure_detector.py"""
import logging
import re
from typing import Optional
from urllib.parse import urljoin

import httpx

from config import SENSITIVE_PATHS, LEAK_PATTERNS, DEFAULT_TIMEOUT
from crawler.async_crawler import PageResult
from detection.finding import Finding

log = logging.getLogger(__name__)

_EXISTS = {200, 206}


class ConfigExposureDetector:
    def __init__(self, client: httpx.AsyncClient, origin: str, timeout: int = DEFAULT_TIMEOUT):
        self.client  = client
        self.origin  = origin
        self.timeout = timeout

    async def run(self) -> list[Finding]:
        import asyncio
        tasks = [self._probe(urljoin(self.origin, p), p) for p in SENSITIVE_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, Finding)]

    async def _probe(self, url: str, path: str) -> Optional[Finding]:
        try:
            resp = await self.client.get(url, timeout=self.timeout, follow_redirects=False)
        except Exception as exc:
            log.debug("Exposure probe failed (%s): %s", url, exc)
            return None

        if resp.status_code not in _EXISTS or len(resp.text.strip()) < 20:
            return None

        sev = _sev(path)
        return Finding(
            vuln_type=f"Exposed Sensitive File: {path}",
            severity=sev,
            url=url, param="<path>", method="GET",
            request_example=f"GET {url}",
            response_indicator=f"HTTP {resp.status_code} — {len(resp.text)} bytes",
            evidence_snippet=resp.text[:200],
            description=(
                f"Server returned {resp.status_code} for {path!r}, which typically "
                "contains credentials, source code, or server configuration."
            ),
            mitigation=(
                f"Deny public access to {path}. Move secrets to environment variables. "
                "Ensure sensitive files are outside the web root."
            ),
            cwe="CWE-538",
            confidence="HIGH",
        )


class InfoLeakDetector:
    _compiled = {name: re.compile(pat) for name, pat in LEAK_PATTERNS.items()}

    def check_page(self, page: PageResult) -> list[Finding]:
        body = page.body or ""
        if not body:
            return []
        findings = []
        for name, regex in self._compiled.items():
            m = regex.search(body)
            if m:
                v = m.group(0)
                redacted = v[:4] + "…[REDACTED]…" + v[-2:] if len(v) > 8 else "[REDACTED]"
                findings.append(Finding(
                    vuln_type=f"Sensitive Data Exposure: {name}",
                    severity=_sev_leak(name),
                    url=page.url, param="<response-body>", method="GET",
                    request_example=f"GET {page.url}",
                    response_indicator=f"Pattern matched: {name}",
                    evidence_snippet=f"…{body[max(0,m.start()-60):m.start()]}{redacted}{body[m.end():m.end()+60]}…",
                    description=(
                        f"Response body matches pattern for '{name}'. "
                        "Sensitive data in HTTP responses may be captured by attackers."
                    ),
                    mitigation=(
                        "Remove sensitive data from responses. Use secret managers, "
                        "environment variables. Suppress stack traces in production."
                    ),
                    cwe="CWE-200",
                    confidence="MEDIUM",
                ))
        return findings


def _sev(path: str) -> str:
    if any(s in path for s in (".env", "id_rsa", "id_dsa", ".bash_history", "wp-config", "database.yml")):
        return "CRITICAL"
    if any(s in path for s in (".git/config", ".htpasswd", "settings.py", "backup.sql", "phpinfo")):
        return "HIGH"
    return "MEDIUM"


def _sev_leak(name: str) -> str:
    if name in {"AWS Access Key", "Generic API Key", "Private Key"}:
        return "CRITICAL"
    if name in {"Password in HTML", "JWT Token", "Basic Auth in URL"}:
        return "HIGH"
    return "MEDIUM"
