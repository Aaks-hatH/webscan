"""detection/xss_detector.py — Async reflected XSS detector."""
import logging
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx

from config import XSS_PROBES, DEFAULT_TIMEOUT
from detection.finding import Finding
from discovery.input_discovery import InputVector

log = logging.getLogger(__name__)


class XSSDetector:
    def __init__(self, client: httpx.AsyncClient, timeout: int = DEFAULT_TIMEOUT):
        self.client  = client
        self.timeout = timeout

    async def test_vector(self, vector: InputVector) -> list[Finding]:
        for probe in XSS_PROBES:
            f = await self._probe(vector, probe)
            if f:
                return [f]
        return []

    async def _probe(self, vector: InputVector, probe: str) -> Optional[Finding]:
        try:
            if vector.method == "GET":
                url  = _inject(vector.url, vector.param_name, probe)
                resp = await self.client.get(url, timeout=self.timeout)
                req_example = f"GET {url}"
            else:
                data = {**vector.form_data, vector.param_name: probe}
                resp = await self.client.post(vector.url, data=data, timeout=self.timeout)
                req_example = f"POST {vector.url}\n\n{urlencode(data)}"
        except Exception as exc:
            log.debug("XSS probe failed (%s): %s", vector.url, exc)
            return None

        if "html" not in resp.headers.get("content-type", "").lower():
            return None
        if probe not in resp.text:
            return None
        escaped = probe.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        if escaped in resp.text and probe not in resp.text:
            return None

        return Finding(
            vuln_type="Reflected XSS Indicator",
            severity="HIGH",
            url=vector.url,
            param=vector.param_name,
            method=vector.method,
            request_example=req_example,
            response_indicator=f"Probe reflected unescaped: {probe!r}",
            evidence_snippet=_snippet(resp.text, probe),
            description=(
                "User-supplied input is reflected directly into the HTML response "
                "without output encoding. An attacker could inject script content "
                "that executes in a victim's browser."
            ),
            mitigation=(
                "HTML-encode all user-supplied output. Use a template engine with "
                "auto-escaping. Apply a strict Content-Security-Policy."
            ),
            cwe="CWE-79",
            confidence="HIGH",
        )


def _inject(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


def _snippet(body: str, probe: str, ctx: int = 120) -> str:
    i = body.find(probe)
    if i == -1:
        return ""
    return "…" + body[max(0, i - ctx // 2): i + len(probe) + ctx // 2] + "…"
