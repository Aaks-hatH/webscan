"""detection/redirect_detector.py"""
import logging
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx

from config import REDIRECT_PAYLOADS, REDIRECT_PARAMS, DEFAULT_TIMEOUT
from detection.finding import Finding
from discovery.input_discovery import InputVector

log = logging.getLogger(__name__)


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
            resp = await self.client.get(url, timeout=self.timeout, follow_redirects=False)
        except Exception as exc:
            log.debug("Redirect probe failed: %s", exc)
            return None

        if resp.status_code not in (301, 302, 303, 307, 308):
            return None
        location = resp.headers.get("location", "")
        if "evil.example.com" not in location:
            return None

        return Finding(
            vuln_type="Open Redirect",
            severity="MEDIUM",
            url=vector.url,
            param=vector.param_name,
            method="GET",
            request_example=f"GET {url}",
            response_indicator=f"HTTP {resp.status_code} Location: {location}",
            description=(
                f"Parameter {vector.param_name!r} accepts arbitrary redirect destinations. "
                "Attackers can craft links through your trusted domain that redirect users "
                "to phishing pages."
            ),
            mitigation=(
                "Validate redirect targets against an allowlist of permitted URLs. "
                "Reject targets with external hosts."
            ),
            cwe="CWE-601",
            confidence="HIGH",
        )
