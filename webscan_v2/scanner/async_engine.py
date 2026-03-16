"""
scanner/async_engine.py — Full async scan pipeline orchestrator.

Architecture
------------
All I/O runs inside a single httpx.AsyncClient, shared by the crawler and
every detector. A semaphore on the crawler limits concurrency. Detection
tasks are gathered in parallel per page/vector. Progress is pushed to an
asyncio.Queue that the WebSocket handler drains in real time.
"""

import asyncio
import logging
import time
import warnings
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx

from api.models import ScanConfig
from config import PROFILES, SEVERITY_ORDER, USER_AGENT, DEFAULT_TIMEOUT
from crawler.async_crawler import AsyncCrawler, PageResult
from detection.finding import Finding
from detection.header_checker import HeaderChecker
from detection.redirect_detector import RedirectDetector
from detection.exposure_detector import ConfigExposureDetector, InfoLeakDetector
from detection.xss_detector import XSSDetector
from detection.sqli_detector import SQLiDetector
from detection.stored_xss import StoredXSSDetector
from detection.blind_sqli import BlindSQLiDetector
from detection.csrf_detector import CSRFDetector
from detection.idor_detector import IDORDetector
from discovery.input_discovery import InputDiscovery

log = logging.getLogger(__name__)

warnings.filterwarnings("ignore", message="Unverified HTTPS request")


@dataclass
class ScanResult:
    target:        str
    duration_s:    float
    pages_crawled: int
    input_vectors: int
    findings:      list[dict] = field(default_factory=list)
    errors:        list[str]  = field(default_factory=list)


class AsyncScannerEngine:
    def __init__(self, config: ScanConfig):
        self.config = config
        # Merge profile defaults with per-scan overrides
        profile_defaults = PROFILES.get(config.profile, PROFILES["standard"]).copy()
        for key, val in config.model_dump().items():
            if key.startswith("run_") and val is not None:
                profile_defaults[key] = val
        self._flags = profile_defaults

    async def run(self, progress: asyncio.Queue) -> ScanResult:
        t0 = time.monotonic()

        client_limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
        async with httpx.AsyncClient(
            headers={"User-Agent": USER_AGENT},
            timeout=DEFAULT_TIMEOUT,
            verify=False,
            follow_redirects=True,
            limits=client_limits,
        ) as client:
            findings: list[Finding] = []
            errors:   list[str]     = []

            # ── Phase 1: Crawl ────────────────────────────────────────────────
            await progress.put({
                "type": "phase",
                "data": {"phase": "crawling", "message": f"Crawling {self.config.target}…"},
            })

            crawler = AsyncCrawler(
                root_url  = self.config.target,
                max_depth = self.config.max_depth,
                max_pages = self.config.max_pages,
                delay     = self.config.delay,
            )

            pages_so_far = 0

            async def on_page(page: PageResult):
                nonlocal pages_so_far
                pages_so_far += 1
                await progress.put({
                    "type": "progress",
                    "data": {
                        "phase": "crawling",
                        "current": pages_so_far,
                        "message": f"Crawled: {page.url}",
                    },
                })

            pages = await crawler.crawl(on_page=on_page)
            valid_pages = [p for p in pages if not p.error]

            await progress.put({
                "type": "progress",
                "data": {"phase": "crawling", "message": f"Crawl complete — {len(valid_pages)} pages"},
            })

            # ── Phase 2: Input discovery ──────────────────────────────────────
            await progress.put({
                "type": "phase",
                "data": {"phase": "discovery", "message": "Discovering input vectors…"},
            })
            surface = InputDiscovery(pages).run()
            vectors = surface.all_vectors

            await progress.put({
                "type": "progress",
                "data": {
                    "phase": "discovery",
                    "message": f"Found {len(vectors)} input vectors across {len(valid_pages)} pages",
                },
            })

            # ── Phase 3: Header checks ────────────────────────────────────────
            if self._flags.get("run_headers"):
                await progress.put({
                    "type": "phase",
                    "data": {"phase": "headers", "message": "Checking security headers…"},
                })
                checker = HeaderChecker()
                seen_origins: set[str] = set()
                for page in valid_pages:
                    origin = _origin(page.url)
                    if origin not in seen_origins:
                        seen_origins.add(origin)
                        new_findings = checker.check_page(page)
                        for f in new_findings:
                            findings.append(f)
                            await _emit_finding(progress, f)

            # ── Phase 4: CSRF checks ──────────────────────────────────────────
            if self._flags.get("run_csrf"):
                await progress.put({
                    "type": "phase",
                    "data": {"phase": "csrf", "message": "Checking for CSRF protection…"},
                })
                csrf_det = CSRFDetector()
                for page in valid_pages:
                    for f in csrf_det.check_page(page):
                        findings.append(f)
                        await _emit_finding(progress, f)

            # ── Phase 5: Info leak & file exposure ────────────────────────────
            if self._flags.get("run_info_leak"):
                await progress.put({
                    "type": "phase",
                    "data": {"phase": "info_leak", "message": "Scanning for data leaks…"},
                })
                leak_det = InfoLeakDetector()
                for page in valid_pages:
                    for f in leak_det.check_page(page):
                        findings.append(f)
                        await _emit_finding(progress, f)

            if self._flags.get("run_exposure"):
                await progress.put({
                    "type": "phase",
                    "data": {"phase": "exposure", "message": "Probing for exposed files…"},
                })
                origin     = _origin(self.config.target)
                exp_det    = ConfigExposureDetector(client, origin)
                exp_finds  = await exp_det.run()
                for f in exp_finds:
                    findings.append(f)
                    await _emit_finding(progress, f)

            # ── Phase 6: Stored XSS (two-phase) ──────────────────────────────
            if self._flags.get("run_stored_xss"):
                await progress.put({
                    "type": "phase",
                    "data": {"phase": "stored_xss", "message": "Testing for stored XSS…"},
                })
                stored_det = StoredXSSDetector(client)
                for f in await stored_det.run(valid_pages):
                    findings.append(f)
                    await _emit_finding(progress, f)

            # ── Phase 7: Per-vector detection (parallel batches) ──────────────
            if vectors:
                await progress.put({
                    "type": "phase",
                    "data": {
                        "phase": "fuzzing",
                        "total": len(vectors),
                        "message": f"Fuzzing {len(vectors)} input vectors…",
                    },
                })

                xss_det   = XSSDetector(client)      if self._flags.get("run_xss")       else None
                sqli_det  = SQLiDetector(client)     if self._flags.get("run_sqli")      else None
                blind_det = BlindSQLiDetector(client)if self._flags.get("run_blind_sqli")else None
                redir_det = RedirectDetector(client) if self._flags.get("run_redirects") else None
                idor_det  = IDORDetector(client)     if self._flags.get("run_idor")      else None

                sem = asyncio.Semaphore(8)

                async def test_one(idx: int, vector):
                    async with sem:
                        local_findings: list[Finding] = []
                        try:
                            tasks = []
                            if xss_det:   tasks.append(xss_det.test_vector(vector))
                            if sqli_det:  tasks.append(sqli_det.test_vector(vector))
                            if blind_det: tasks.append(blind_det.test_vector(vector))
                            if redir_det: tasks.append(redir_det.test_vector(vector))
                            if idor_det:  tasks.append(idor_det.test_vector(vector))

                            results = await asyncio.gather(*tasks, return_exceptions=True)
                            for r in results:
                                if isinstance(r, list):
                                    local_findings.extend(r)
                        except Exception as exc:
                            errors.append(f"Vector error [{vector.url}:{vector.param_name}]: {exc}")

                        await progress.put({
                            "type": "progress",
                            "data": {
                                "phase": "fuzzing",
                                "current": idx + 1,
                                "total": len(vectors),
                                "message": f"[{idx+1}/{len(vectors)}] {vector.method} {vector.url} [{vector.param_name}]",
                                "new_findings": len(local_findings),
                            },
                        })
                        return local_findings

                batch_results = await asyncio.gather(
                    *[test_one(i, v) for i, v in enumerate(vectors)],
                    return_exceptions=True,
                )
                for r in batch_results:
                    if isinstance(r, list):
                        for f in r:
                            findings.append(f)
                            await _emit_finding(progress, f)

        # ── Finalise ──────────────────────────────────────────────────────────
        findings = _dedup_and_sort(findings)

        return ScanResult(
            target        = self.config.target,
            duration_s    = round(time.monotonic() - t0, 2),
            pages_crawled = len(valid_pages),
            input_vectors = len(vectors),
            findings      = [f.to_dict() for f in findings],
            errors        = errors,
        )


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _emit_finding(q: asyncio.Queue, f: Finding) -> None:
    await q.put({"type": "finding", "data": f.to_dict()})


def _dedup_and_sort(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.vuln_type, f.url, f.param, f.method)
        if key not in seen:
            seen.add(key)
            out.append(f)
    out.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return out


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"
