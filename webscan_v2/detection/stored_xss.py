"""
detection/stored_xss.py

Two-phase stored XSS detection:
  Phase 1 — For every POST form, submit a unique tagged probe in each field.
  Phase 2 — Re-fetch all previously seen pages and look for probe strings
             in the response body. A probe appearing outside its own submission
             page is a strong stored XSS indicator.
"""

import asyncio
import logging
import uuid
from urllib.parse import urlencode

import httpx

from config import USER_AGENT, DEFAULT_TIMEOUT
from detection.finding import Finding
from crawler.async_crawler import PageResult, DiscoveredForm

log = logging.getLogger(__name__)


class StoredXSSDetector:
    def __init__(self, client: httpx.AsyncClient, timeout: int = DEFAULT_TIMEOUT):
        self.client  = client
        self.timeout = timeout

    async def run(self, pages: list[PageResult]) -> list[Finding]:
        """Full two-phase run given the complete crawl output."""
        # Phase 1: submit probes
        probe_map: dict[str, tuple[str, str]] = {}   # probe_tag → (form_url, param_name)
        submission_tasks = []

        for page in pages:
            for form in page.forms:
                if form.method != "POST":
                    continue
                for inp in form.inputs:
                    if inp.input_type in ("submit", "button", "reset", "hidden", "file"):
                        continue
                    tag = uuid.uuid4().hex[:8]
                    probe = f'wscan-stored-{tag}'
                    probe_map[probe] = (form.action, inp.name)
                    submission_tasks.append(self._submit(form, inp.name, probe))

        if not submission_tasks:
            return []

        await asyncio.gather(*submission_tasks, return_exceptions=True)
        log.info("Stored XSS: submitted %d probes", len(probe_map))

        # Phase 2: re-fetch pages and search for probes
        await asyncio.sleep(1.0)  # let the server process submissions

        findings: list[Finding] = []
        check_tasks = [self._check_page(url, probe_map) for url in {p.url for p in pages}]
        results = await asyncio.gather(*check_tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    async def _submit(self, form: DiscoveredForm, target_param: str, probe: str) -> None:
        data = {inp.name: inp.value for inp in form.inputs
                if inp.input_type not in ("submit", "button", "reset")}
        data[target_param] = probe
        try:
            await self.client.post(form.action, data=data, timeout=self.timeout)
        except Exception as exc:
            log.debug("Stored XSS submit failed (%s): %s", form.action, exc)

    async def _check_page(
        self,
        url: str,
        probe_map: dict[str, tuple[str, str]],
    ) -> list[Finding]:
        try:
            resp = await self.client.get(url, timeout=self.timeout)
        except Exception:
            return []

        body     = resp.text
        findings = []

        for probe, (form_url, param_name) in probe_map.items():
            if probe in body:
                findings.append(Finding(
                    vuln_type="Stored XSS Indicator",
                    severity="HIGH",
                    url=url,
                    param=param_name,
                    method="POST",
                    request_example=(
                        f"POST {form_url}\n\n"
                        f"{param_name}={probe}"
                    ),
                    response_indicator=f"Probe {probe!r} found in {url}",
                    evidence_snippet=_snippet(body, probe),
                    description=(
                        "A probe submitted via a form appeared unescaped in a subsequent "
                        "page response. This indicates the application stores user input "
                        "and renders it without encoding — a classic stored (persistent) "
                        "XSS vulnerability. Attackers can inject scripts that execute for "
                        "every user who views the affected page."
                    ),
                    mitigation=(
                        "HTML-encode all stored user content before rendering. "
                        "Use template auto-escaping. Apply a strict Content-Security-Policy. "
                        "Sanitise rich-text input server-side with a library like DOMPurify "
                        "(client) or bleach (Python server-side)."
                    ),
                    cwe="CWE-79",
                    confidence="HIGH",
                ))

        return findings


def _snippet(body: str, probe: str, ctx: int = 120) -> str:
    i = body.find(probe)
    if i == -1:
        return ""
    return "…" + body[max(0, i - ctx // 2): i + len(probe) + ctx // 2] + "…"
