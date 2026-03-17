"""
detection/js_secret_extractor.py — Extracts hardcoded secrets from JavaScript files.

Fetches all JS files found during crawling and scans them for:
  - API keys and tokens (AWS, Stripe, SendGrid, Twilio, etc.)
  - Hardcoded passwords and secrets
  - Internal hostnames and IP addresses
  - Private keys and certificates
  - Auth endpoints with embedded credentials
  - Admin credentials and backdoor tokens
  - Database connection strings
  - JWT secrets hardcoded as string literals

Designed to NOT trigger Planit's FUZZ_PATTERNS — it only fetches
.js files that the crawler already discovered legitimately.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from config import DEFAULT_TIMEOUT
from detection.finding import Finding
from crawler.async_crawler import PageResult

log = logging.getLogger(__name__)


# ── Secret patterns ───────────────────────────────────────────────────────────

@dataclass
class SecretPattern:
    name:       str
    regex:      re.Pattern
    severity:   str
    context_re: Optional[re.Pattern] = None  # optional surrounding context matcher
    false_positive_re: Optional[re.Pattern] = None  # exclude if matched


_PATTERNS: list[SecretPattern] = [
    # AWS
    SecretPattern("AWS Access Key ID",      re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                     "CRITICAL"),
    SecretPattern("AWS Secret Access Key",  re.compile(r"(?i)aws.{0,30}secret.{0,10}[\"'][0-9a-zA-Z/+]{40}[\"']"), "CRITICAL"),

    # Stripe
    SecretPattern("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),             "CRITICAL"),
    SecretPattern("Stripe Test Secret Key", re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b"),             "HIGH"),
    SecretPattern("Stripe Publishable Key", re.compile(r"\bpk_(?:live|test)_[0-9a-zA-Z]{24,}\b"),   "MEDIUM"),

    # SendGrid / Twilio / Mailgun
    SecretPattern("SendGrid API Key",       re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"), "CRITICAL"),
    SecretPattern("Twilio Account SID",     re.compile(r"\bAC[a-z0-9]{32}\b"),                       "HIGH"),
    SecretPattern("Twilio Auth Token",      re.compile(r"(?i)twilio.{0,30}[\"'][a-f0-9]{32}[\"']"),  "CRITICAL"),
    SecretPattern("Mailgun API Key",        re.compile(r"\bkey-[a-z0-9]{32}\b"),                     "CRITICAL"),

    # GitHub / GitLab
    SecretPattern("GitHub Token",           re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),                  "CRITICAL"),
    SecretPattern("GitHub OAuth Token",     re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),                  "CRITICAL"),
    SecretPattern("GitLab Personal Token",  re.compile(r"\bglpat-[A-Za-z0-9_-]{20}\b"),              "CRITICAL"),

    # Google
    SecretPattern("Google API Key",         re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),                "HIGH"),
    SecretPattern("Google OAuth Client",    re.compile(r"\b[0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com\b"), "MEDIUM"),

    # JWT secrets in code
    SecretPattern("Hardcoded JWT Secret",
                  re.compile(r"(?i)(?:jwt_?secret|secret_?key|signing_?key|token_?secret)\s*[:=]\s*[\"'][^\"']{8,}[\"']"),
                  "CRITICAL"),
    SecretPattern("JWT Secret Variable",
                  re.compile(r"(?i)const\s+(?:JWT_SECRET|SECRET_KEY|SIGNING_KEY)\s*=\s*[\"'][^\"']{8,}[\"']"),
                  "CRITICAL"),

    # Generic secrets / passwords
    SecretPattern("Hardcoded Password",
                  re.compile(r"(?i)password\s*[:=]\s*[\"'][^\"']{6,}[\"']"),
                  "HIGH",
                  false_positive_re=re.compile(r"(?i)(placeholder|example|changeme|your.password|sample|test123|password123)")),
    SecretPattern("Hardcoded API Key",
                  re.compile(r"(?i)api_?key\s*[:=]\s*[\"'][0-9a-zA-Z_\-]{16,}[\"']"),
                  "HIGH",
                  false_positive_re=re.compile(r"(?i)(your.api.key|replace.this|placeholder|xxxx)")),
    SecretPattern("Hardcoded Bearer Token",
                  re.compile(r"(?i)bearer\s+[0-9a-zA-Z_\-\.]{20,}"),
                  "HIGH"),
    SecretPattern("Hardcoded Authorization Header",
                  re.compile(r"(?i)[\"']?authorization[\"']?\s*:\s*[\"']bearer\s+[0-9a-zA-Z_\-\.]{20,}[\"']"),
                  "CRITICAL"),

    # Database connection strings
    SecretPattern("Database Connection String",
                  re.compile(r"(?:mongodb|postgres|postgresql|mysql|redis):\/\/[^:\"'\s]+:[^@\"'\s]+@[^\"'\s]+"),
                  "CRITICAL"),
    SecretPattern("Database Password in URL",
                  re.compile(r"(?i)(?:db_?pass(?:word)?|database_?pass(?:word)?)\s*[:=]\s*[\"'][^\"']{4,}[\"']"),
                  "CRITICAL"),

    # Private keys
    SecretPattern("RSA/EC Private Key",
                  re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
                  "CRITICAL"),

    # Internal infrastructure
    SecretPattern("Internal Hostname/IP",
                  re.compile(r"(?i)https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?::\d+)?"),
                  "MEDIUM"),
    SecretPattern("Internal API Endpoint",
                  re.compile(r"(?i)[\"'`]/api/(?:admin|internal|cc|employees|config|secret)[\"'`/]"),
                  "MEDIUM"),

    # Misc high-value
    SecretPattern("Slack Webhook",
                  re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
                  "HIGH"),
    SecretPattern("Discord Webhook",
                  re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"),
                  "HIGH"),
    SecretPattern("Firebase Config",
                  re.compile(r"(?i)firebase[^{]{0,50}apiKey\s*:\s*[\"'][A-Za-z0-9_-]{30,}[\"']"),
                  "HIGH"),
    SecretPattern("Hardcoded Admin Credential",
                  re.compile(r"(?i)admin.{0,20}(?:password|secret|key|token)\s*[:=]\s*[\"'][^\"']{4,}[\"']"),
                  "CRITICAL"),
]


# ── JS file discovery ─────────────────────────────────────────────────────────

_JS_SRC_RE   = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
_INLINE_RE   = re.compile(r'<script(?:[^>]*)>(.*?)</script>', re.DOTALL | re.IGNORECASE)


def _find_js_urls(pages: list[PageResult], origin: str) -> list[str]:
    """Extract all unique JS file URLs from crawled pages."""
    urls: list[str] = []
    seen: set[str]  = set()

    for page in pages:
        body = page.body or ""
        for match in _JS_SRC_RE.finditer(body):
            src = match.group(1)
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = origin + src
            elif not src.startswith("http"):
                src = urljoin(page.url, src)

            # Only scan same-origin JS (don't scan CDN bundles)
            if urlparse(src).netloc == urlparse(origin).netloc:
                if src not in seen:
                    seen.add(src)
                    urls.append(src)

    return urls


# ── Scanner ───────────────────────────────────────────────────────────────────

@dataclass
class SecretMatch:
    pattern_name: str
    severity:     str
    match_text:   str
    context:      str
    source_url:   str
    line_number:  int


class JSSecretExtractor:
    """
    Downloads JS files and scans them for hardcoded secrets.
    Also scans inline scripts from crawled pages.
    """

    def __init__(
        self,
        client:  httpx.AsyncClient,
        origin:  str,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        self.client  = client
        self.origin  = origin.rstrip("/")
        self.timeout = timeout

    async def run(self, pages: list[PageResult]) -> list[Finding]:
        findings: list[Finding] = []
        seen_matches: set[tuple] = set()

        # 1. Scan inline scripts from crawled pages
        for page in pages:
            body = page.body or ""
            for inline_match in _INLINE_RE.finditer(body):
                script_content = inline_match.group(1)
                matches = _scan_text(script_content, page.url)
                for m in matches:
                    key = (m.pattern_name, m.match_text[:60], m.source_url)
                    if key not in seen_matches:
                        seen_matches.add(key)
                        findings.append(_match_to_finding(m))

        # 2. Fetch and scan external JS files
        js_urls = _find_js_urls(pages, self.origin)
        log.info("[JSSecrets] Scanning %d JS file(s) + inline scripts", len(js_urls))

        import asyncio
        sem = asyncio.Semaphore(4)

        async def scan_js(url: str) -> list[Finding]:
            async with sem:
                try:
                    resp = await self.client.get(url, timeout=self.timeout, follow_redirects=True)
                    if resp.status_code != 200:
                        return []
                    ct = resp.headers.get("content-type", "")
                    if "javascript" not in ct and "text" not in ct and not url.endswith(".js"):
                        return []
                    text = resp.text
                except Exception as exc:
                    log.debug("[JSSecrets] Failed to fetch %s: %s", url, exc)
                    return []

                local: list[Finding] = []
                for m in _scan_text(text, url):
                    key = (m.pattern_name, m.match_text[:60], url)
                    if key not in seen_matches:
                        seen_matches.add(key)
                        local.append(_match_to_finding(m))
                return local

        results = await asyncio.gather(*[scan_js(u) for u in js_urls], return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings


# ── Helpers ───────────────────────────────────────────────────────────────────

def _scan_text(text: str, source_url: str) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    lines   = text.splitlines()

    for pat in _PATTERNS:
        for line_num, line in enumerate(lines, 1):
            m = pat.regex.search(line)
            if not m:
                continue
            # Apply false positive filter
            if pat.false_positive_re and pat.false_positive_re.search(line):
                continue
            # Context window (3 lines either side)
            start = max(0, line_num - 4)
            end   = min(len(lines), line_num + 3)
            ctx   = "\n".join(lines[start:end])

            matches.append(SecretMatch(
                pattern_name=pat.name,
                severity=pat.severity,
                match_text=m.group(0)[:200],
                context=ctx[:500],
                source_url=source_url,
                line_number=line_num,
            ))
            break  # one match per pattern per file

    return matches


def _match_to_finding(m: SecretMatch) -> Finding:
    # Redact the actual secret value for safety in the report
    redacted = re.sub(r"([\"'`])[^\"'`]{6,}([\"'`])", r"\1***\2", m.match_text)

    return Finding(
        vuln_type=f"Hardcoded Secret in JavaScript: {m.pattern_name}",
        severity=m.severity,
        url=m.source_url,
        param=f"Line {m.line_number}",
        method="GET",
        request_example=f"GET {m.source_url}",
        response_indicator=f"Pattern: {m.pattern_name} at line {m.line_number}",
        evidence_snippet=f"Match: {redacted}\n\nContext:\n{m.context}",
        description=(
            f"A {m.pattern_name} was found hardcoded in a JavaScript file at "
            f"line {m.line_number} of {m.source_url}. Hardcoded secrets in "
            "client-side JS are visible to anyone who views the source."
        ),
        mitigation=(
            "Never hardcode secrets in frontend code. Use environment variables "
            "server-side and expose only the minimum necessary to the client "
            "(e.g. a public key, never a secret key). Rotate any exposed credentials immediately."
        ),
        cwe="CWE-798",
        confidence="HIGH" if m.severity in ("CRITICAL", "HIGH") else "MEDIUM",
    )
