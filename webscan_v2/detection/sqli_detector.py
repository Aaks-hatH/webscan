"""detection/sqli_detector.py — Async error-based SQLi detector."""
import logging
from typing import Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import httpx

from config import SQLI_PROBES, SQLI_ERROR_SIGNATURES, DEFAULT_TIMEOUT
from detection.finding import Finding
from discovery.input_discovery import InputVector

log = logging.getLogger(__name__)


class SQLiDetector:
    def __init__(self, client: httpx.AsyncClient, timeout: int = DEFAULT_TIMEOUT):
        self.client  = client
        self.timeout = timeout

    async def test_vector(self, vector: InputVector) -> list[Finding]:
        baseline = await self._baseline(vector)
        for probe in SQLI_PROBES:
            f = await self._probe(vector, probe, baseline)
            if f:
                return [f]
        return []

    async def _baseline(self, vector: InputVector) -> str:
        try:
            if vector.method == "GET":
                resp = await self.client.get(vector.url, timeout=self.timeout)
            else:
                resp = await self.client.post(vector.url, data=vector.form_data, timeout=self.timeout)
            return resp.text.lower()
        except Exception:
            return ""

    async def _probe(self, vector: InputVector, probe: str, baseline: str) -> Optional[Finding]:
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
            log.debug("SQLi probe failed (%s): %s", vector.url, exc)
            return None

        body_lower = resp.text.lower()
        for sig in SQLI_ERROR_SIGNATURES:
            if sig in body_lower and sig not in baseline:
                return Finding(
                    vuln_type="SQL Injection Indicator",
                    severity="CRITICAL",
                    url=vector.url,
                    param=vector.param_name,
                    method=vector.method,
                    request_example=req_example,
                    response_indicator=f"DB error signature detected: {sig!r}",
                    evidence_snippet=_snippet(resp.text, sig.split()[0]),
                    description=(
                        f"Injecting {probe!r} triggered a database error. "
                        "The parameter is likely concatenated unsanitised into a SQL query."
                    ),
                    mitigation=(
                        "Use parameterised queries / prepared statements. Never concatenate "
                        "user input into SQL. Suppress raw DB errors from HTTP responses."
                    ),
                    cwe="CWE-89",
                    cvss_score=9.8,
                    confidence="HIGH",
                )
        return None


def _inject(url: str, param: str, value: str) -> str:
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(p._replace(query=urlencode(qs, doseq=True)))


def _snippet(body: str, kw: str, ctx: int = 200) -> str:
    i = body.lower().find(kw.lower())
    if i == -1:
        return body[:200]
    return "…" + body[max(0, i - ctx // 2): i + len(kw) + ctx // 2] + "…"
