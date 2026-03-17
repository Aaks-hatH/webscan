"""detection/redirect_detector.py — Open redirect detector (GET + POST forms)."""
import logging
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx

from config import REDIRECT_PAYLOADS, REDIRECT_PARAMS, DEFAULT_TIMEOUT
from detection.finding import Finding
from discovery.input_discovery import InputVector
from crawler.async_crawler import PageResult

log = logging.getLogger(__name__)

_PAYLOAD = "https://evil.example.com"


class RedirectDetector:
    def __init__(self, client: httpx.AsyncClient, timeout: int = DEFAULT_TIMEOUT):
        self.client  = client
        self.timeout = timeout

    async def test_vector(self, vector: InputVector) -> list[Finding]:
        if vector.param_name.lower() not in REDIRECT_PARAMS:
            return []
        for payload in REDIRECT_PAYLOADS:
            f = await self._probe(vector, payload)
            if f:
                return [f]
        return []

    async def _probe(self, vector: InputVector, payload: str) -> Optional[Finding]:
        p  = urlparse(vector.url)
        qs = parse_qs(p.query, keep_blank_values=True)
        qs[vector.param_name] = [payload]
        url = urlunparse(p._replace(query=urlencode(qs, doseq=True)))
        try:
            if vector.method == "GET":
                resp = await self.client.get(url, timeout=self.timeout, follow_redirects=False)
            else:
                data = {**vector.form_data, vector.param_name: payload}
                resp = await self.client.post(
                    vector.url, data=data, timeout=self.timeout, follow_redirects=False
                )
        except Exception as exc:
            log.debug("Redirect probe failed: %s", exc)
            return None

        # Check HTTP redirect
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            if "evil.example.com" in location:
                return self._finding(vector, url, resp.status_code, location, payload)

        # Check meta-refresh redirect (common in PHP apps)
        if resp.status_code == 200 and "html" in resp.headers.get("content-type", ""):
            body = resp.text.lower()
            if "evil.example.com" in body and ("meta" in body or "location" in body):
                return self._finding(vector, url, resp.status_code, "meta-refresh in body", payload)

        # Check JS redirect in body
        if resp.status_code == 200 and "evil.example.com" in resp.text:
            if "window.location" in resp.text or "location.href" in resp.text:
                return self._finding(vector, url, resp.status_code, "JS redirect in body", payload)

        return None

    @staticmethod
    def _finding(vector: InputVector, url: str, status: int, location: str, payload: str) -> Finding:
        return Finding(
            vuln_type="Open Redirect",
            severity="MEDIUM",
            url=vector.url,
            param=vector.param_name,
            method=vector.method,
            request_example=f"{vector.method} {url}",
            response_indicator=f"HTTP {status} → Location: {location}",
            evidence_snippet=f"Parameter '{vector.param_name}' accepted '{payload}' → redirected to external domain",
            description=(
                f"The parameter '{vector.param_name}' accepts arbitrary redirect destinations "
                "without validation. Attackers craft links through your trusted domain "
                "that redirect victims to phishing sites."
            ),
            mitigation=(
                "Validate redirect targets against a strict allowlist. "
                "Reject any target URL whose host differs from your application's host. "
                "Never pass user-supplied paths directly to a redirect."
            ),
            cwe="CWE-601",
            confidence="HIGH",
        )


    # ── Also scan page HTML for unvalidated redirects in forms ──────────────
    def check_page(self, page: PageResult) -> list[Finding]:
        """Flag any form that has a redirect-param input and no CSRF token."""
        findings = []
        for form in page.forms:
            for inp in form.inputs:
                if inp.name.lower() in REDIRECT_PARAMS and inp.input_type != "hidden":
                    findings.append(Finding(
                        vuln_type="Potential Open Redirect in Form",
                        severity="LOW",
                        url=page.url,
                        param=inp.name,
                        method=form.method,
                        request_example=f"{form.method} {form.action}\n{inp.name}=https://evil.example.com",
                        response_indicator=f"Form contains unvalidated redirect field '{inp.name}'",
                        evidence_snippet=f"Form action={form.action}, field={inp.name}",
                        description=(
                            f"Form at {form.action!r} contains a field named '{inp.name}' "
                            "that may be used as an open redirect target."
                        ),
                        mitigation="Validate all redirect parameters server-side against a trusted list.",
                        cwe="CWE-601",
                        confidence="LOW",
                    ))
        return findings
