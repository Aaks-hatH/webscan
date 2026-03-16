"""
detection/blind_sqli.py

Time-based blind SQL injection detection.

Strategy
--------
1. Establish a baseline response time for the parameter (average of 2 requests).
2. Inject payloads that instruct several database backends to sleep for 3 seconds.
3. If the response time exceeds (baseline + THRESHOLD), the payload likely
   caused a server-side delay — indicating time-based blind SQLi.

The payloads do not modify, read, or delete any data. They only cause a
conditional delay, which is the standard safe detection technique.
"""

import asyncio
import logging
import time
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx

from config import BLIND_SQLI_PAYLOADS, BLIND_SQLI_DELAY_THRESHOLD, DEFAULT_TIMEOUT
from detection.finding import Finding
from discovery.input_discovery import InputVector

log = logging.getLogger(__name__)

_BASELINE_SAMPLES = 2
_MAX_PAYLOAD_TIMEOUT = 12   # seconds — gives 3s sleep + 9s buffer


class BlindSQLiDetector:
    def __init__(self, client: httpx.AsyncClient, timeout: int = DEFAULT_TIMEOUT):
        self.client  = client
        self.timeout = timeout

    async def test_vector(self, vector: InputVector) -> list[Finding]:
        baseline_ms = await self._baseline(vector)
        if baseline_ms < 0:
            return []   # baseline failed

        threshold_s = (baseline_ms / 1000) + BLIND_SQLI_DELAY_THRESHOLD

        for payload, backend_hint in BLIND_SQLI_PAYLOADS:
            finding = await self._probe(vector, payload, backend_hint, threshold_s)
            if finding:
                return [finding]

        return []

    async def _baseline(self, vector: InputVector) -> float:
        """Returns average response time in ms, or -1 on failure."""
        times = []
        for _ in range(_BASELINE_SAMPLES):
            try:
                t0 = time.monotonic()
                if vector.method == "GET":
                    url = _inject_param(vector.url, vector.param_name, vector.example_value or "1")
                    await self.client.get(url, timeout=self.timeout)
                else:
                    data = {**vector.form_data, vector.param_name: vector.example_value or "1"}
                    await self.client.post(vector.url, data=data, timeout=self.timeout)
                times.append((time.monotonic() - t0) * 1000)
            except Exception:
                return -1.0
        return sum(times) / len(times)

    async def _probe(
        self,
        vector: InputVector,
        payload: str,
        backend_hint: str,
        threshold_s: float,
    ) -> Optional[Finding]:
        try:
            t0 = time.monotonic()
            if vector.method == "GET":
                url = _inject_param(vector.url, vector.param_name, payload)
                await self.client.get(url, timeout=_MAX_PAYLOAD_TIMEOUT)
                req_example = f"GET {url}"
            else:
                data = {**vector.form_data, vector.param_name: payload}
                await self.client.post(vector.url, data=data, timeout=_MAX_PAYLOAD_TIMEOUT)
                req_example = (
                    f"POST {vector.url}\n\n"
                    + urlencode({**vector.form_data, vector.param_name: payload})
                )
            elapsed = time.monotonic() - t0
        except httpx.TimeoutException:
            # Timeout itself is a strong signal — the sleep exceeded our limit
            elapsed = _MAX_PAYLOAD_TIMEOUT + 1
            req_example = f"{vector.method} {vector.url} [{vector.param_name}={payload!r}]"
        except Exception as exc:
            log.debug("Blind SQLi probe failed (%s): %s", vector.url, exc)
            return None

        if elapsed < threshold_s:
            return None

        return Finding(
            vuln_type="Blind SQL Injection (Time-Based)",
            severity="CRITICAL",
            url=vector.url,
            param=vector.param_name,
            method=vector.method,
            request_example=req_example,
            response_indicator=(
                f"Response delayed {elapsed:.2f}s "
                f"(threshold: {threshold_s:.2f}s). "
                f"Payload targeted {backend_hint}."
            ),
            description=(
                f"Injecting a time-delay SQL payload ({backend_hint}) into the "
                f"parameter {vector.param_name!r} caused the server to respond "
                f"{elapsed:.1f}s later than the baseline. This strongly indicates "
                "the parameter is passed unsanitised into a SQL query, and the "
                "database executed the injected SLEEP/WAITFOR instruction. "
                "The application does not produce error messages (hence 'blind'), "
                "but the time oracle confirms exploitability."
            ),
            mitigation=(
                "Use parameterised queries / prepared statements for all database "
                "queries. Never concatenate user input into SQL strings. "
                "Validate and whitelist expected input formats (numeric, alphanumeric, "
                "date format) before passing to any query. Apply a WAF as a secondary "
                "defence layer."
            ),
            cwe="CWE-89",
            cvss_score=9.8,
            confidence="HIGH",
        )


def _inject_param(url: str, param: str, value: str) -> str:
    p      = urlparse(url)
    params = parse_qs(p.query, keep_blank_values=True)
    params[param] = [value]
    return urlunparse(p._replace(query=urlencode(params, doseq=True)))
