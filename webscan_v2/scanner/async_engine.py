"""
scanner/async_engine.py — Full async scan pipeline with API discovery.

New in this version:
  - SPA detection before file exposure (eliminates false positives)
  - JS bundle parsing to discover API endpoints
  - OpenAPI/Swagger auto-import
  - API fuzzing (auth enforcement, error disclosure, mass assignment)
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
from config import PROFILES, SEVERITY_ORDER, USER_AGENT, DEFAULT_TIMEOUT, get_browser_headers, get_user_agent
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
from detection.spa_detector import SPADetector
from detection.api_fuzzer import APIFuzzer, OpenAPIImporter
from discovery.input_discovery import InputDiscovery
from discovery.js_extractor import JSEndpointExtractor

log = logging.getLogger(__name__)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")


@dataclass
class ScanResult:
    target:        str
    duration_s:    float
    pages_crawled: int
    input_vectors: int
    api_endpoints: int = 0
    findings:      list[dict] = field(default_factory=list)
    errors:        list[str]  = field(default_factory=list)


class AsyncScannerEngine:
    def __init__(self, config: ScanConfig):
        self.config = config
        profile_defaults = PROFILES.get(config.profile, PROFILES["standard"]).copy()
        for key, val in config.model_dump().items():
            if key.startswith("run_") and val is not None:
                profile_defaults[key] = val
        self._flags = profile_defaults

    async def run(self, progress: asyncio.Queue) -> ScanResult:
        t0 = time.monotonic()

        client_limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)

        # Rotate User-Agent on every request via event hook
        async def _rotate_ua(request):
            request.headers["user-agent"] = get_user_agent()

        async with httpx.AsyncClient(
            headers=get_browser_headers(self.config.target),
            timeout=DEFAULT_TIMEOUT,
            verify=False,
            follow_redirects=True,
            limits=client_limits,
            event_hooks={"request": [_rotate_ua]},
        ) as client:
            findings: list[Finding] = []
            errors:   list[str]     = []
            origin = _origin(self.config.target)

            # ── Phase 1: SPA Detection ────────────────────────────────────────
            await progress.put({"type": "phase", "data": {
                "phase": "spa_detect",
                "message": f"Analysing target architecture…",
            }})
            spa_det     = SPADetector(client)
            spa_profile = await spa_det.detect(origin)
            if spa_profile.is_spa:
                await progress.put({"type": "progress", "data": {
                    "phase": "spa_detect",
                    "message": f"SPA detected ({spa_profile.framework_hint}) — file exposure false-positive filtering enabled",
                }})
            else:
                await progress.put({"type": "progress", "data": {
                    "phase": "spa_detect",
                    "message": "Traditional server-side app detected",
                }})

            # ── Phase 2: Crawl ────────────────────────────────────────────────
            await progress.put({"type": "phase", "data": {
                "phase": "crawling",
                "message": f"Crawling {self.config.target}…",
            }})

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
                await progress.put({"type": "progress", "data": {
                    "phase": "crawling",
                    "current": pages_so_far,
                    "message": f"Crawled: {page.url}",
                }})

            pages       = await crawler.crawl(on_page=on_page)
            valid_pages = [p for p in pages if not p.error]
            await progress.put({"type": "progress", "data": {
                "phase": "crawling",
                "message": f"Crawl complete — {len(valid_pages)} pages",
            }})

            # ── Phase 3: Input discovery (HTML forms + query params) ──────────
            await progress.put({"type": "phase", "data": {
                "phase": "discovery",
                "message": "Discovering HTML input vectors…",
            }})
            surface = InputDiscovery(pages).run()
            vectors = surface.all_vectors
            await progress.put({"type": "progress", "data": {
                "phase": "discovery",
                "message": f"Found {len(vectors)} HTML input vectors",
            }})

            # ── Phase 4: API discovery (JS bundles + OpenAPI) ─────────────────
            await progress.put({"type": "phase", "data": {
                "phase": "api_discovery",
                "message": "Extracting API endpoints from JS bundles…",
            }})

            # Try OpenAPI first (most accurate)
            openapi_importer = OpenAPIImporter(client, origin)
            api_vectors      = await openapi_importer.discover()

            if api_vectors:
                await progress.put({"type": "progress", "data": {
                    "phase": "api_discovery",
                    "message": f"OpenAPI spec found — {len(api_vectors)} documented endpoints",
                }})
            else:
                # Fall back to JS bundle extraction
                js_extractor = JSEndpointExtractor(client, origin)
                js_result    = await js_extractor.run(valid_pages)
                api_vectors  = js_extractor.to_input_vectors(js_result)

                if js_result.base_urls:
                    await progress.put({"type": "progress", "data": {
                        "phase": "api_discovery",
                        "message": f"Base URLs detected: {js_result.base_urls[:3]}",
                    }})

                await progress.put({"type": "progress", "data": {
                    "phase": "api_discovery",
                    "message": (
                        f"JS extraction complete — "
                        f"{len(js_result.js_files)} bundles parsed, "
                        f"{len(api_vectors)} API endpoints discovered"
                    ),
                }})

            # Merge: HTML vectors + API vectors
            all_vectors = vectors + api_vectors

            # ── Phase 5: Security headers ─────────────────────────────────────
            if self._flags.get("run_headers"):
                await progress.put({"type": "phase", "data": {
                    "phase": "headers",
                    "message": "Checking security headers…",
                }})
                checker = HeaderChecker()
                seen_origins: set[str] = set()
                for page in valid_pages:
                    o = _origin(page.url)
                    if o not in seen_origins:
                        seen_origins.add(o)
                        for f in checker.check_page(page):
                            findings.append(f)
                            await _emit_finding(progress, f)

            # ── Phase 6: CSRF ─────────────────────────────────────────────────
            if self._flags.get("run_csrf"):
                await progress.put({"type": "phase", "data": {
                    "phase": "csrf", "message": "Checking for CSRF protection…",
                }})
                csrf_det = CSRFDetector()
                for page in valid_pages:
                    for f in csrf_det.check_page(page):
                        findings.append(f)
                        await _emit_finding(progress, f)

            # ── Phase 7: Info leak ────────────────────────────────────────────
            if self._flags.get("run_info_leak"):
                await progress.put({"type": "phase", "data": {
                    "phase": "info_leak", "message": "Scanning for data leaks…",
                }})
                leak_det = InfoLeakDetector()
                for page in valid_pages:
                    for f in leak_det.check_page(page):
                        findings.append(f)
                        await _emit_finding(progress, f)

            # ── Phase 8: File exposure (with SPA filter) ──────────────────────
            if self._flags.get("run_exposure"):
                await progress.put({"type": "phase", "data": {
                    "phase": "exposure",
                    "message": "Probing for exposed files"
                    + (" (SPA filter active)" if spa_profile.is_spa else "") + "…",
                }})
                exp_det = ConfigExposureDetector(client, origin, spa_profile=spa_profile)
                for f in await exp_det.run():
                    findings.append(f)
                    await _emit_finding(progress, f)

            # ── Phase 9: Stored XSS ───────────────────────────────────────────
            if self._flags.get("run_stored_xss"):
                await progress.put({"type": "phase", "data": {
                    "phase": "stored_xss", "message": "Testing for stored XSS…",
                }})
                for f in await StoredXSSDetector(client).run(valid_pages):
                    findings.append(f)
                    await _emit_finding(progress, f)

            # ── Phase 10: API fuzzing ─────────────────────────────────────────
            if api_vectors and self._flags.get("run_api_fuzz", True):
                await progress.put({"type": "phase", "data": {
                    "phase": "api_fuzz",
                    "total": len(api_vectors),
                    "message": f"Fuzzing {len(api_vectors)} API endpoints…",
                }})
                api_fuzzer = APIFuzzer(client, origin)
                api_sem    = asyncio.Semaphore(5)

                async def fuzz_one(idx: int, vec):
                    async with api_sem:
                        local: list[Finding] = []
                        try:
                            local = await api_fuzzer.test_endpoint(vec)
                        except Exception as exc:
                            errors.append(f"API fuzz error [{vec.url}]: {exc}")
                        await progress.put({"type": "progress", "data": {
                            "phase": "api_fuzz",
                            "current": idx + 1,
                            "total": len(api_vectors),
                            "message": f"[{idx+1}/{len(api_vectors)}] API: {vec.url}",
                            "new_findings": len(local),
                        }})
                        return local

                api_results = await asyncio.gather(
                    *[fuzz_one(i, v) for i, v in enumerate(api_vectors)],
                    return_exceptions=True,
                )
                for r in api_results:
                    if isinstance(r, list):
                        for f in r:
                            findings.append(f)
                            await _emit_finding(progress, f)

            # ── Phase 11: HTML input fuzzing (XSS, SQLi, redirects, IDOR) ─────
            if all_vectors:
                await progress.put({"type": "phase", "data": {
                    "phase": "fuzzing",
                    "total": len(all_vectors),
                    "message": f"Fuzzing {len(all_vectors)} total input vectors…",
                }})

                xss_det   = XSSDetector(client)       if self._flags.get("run_xss")        else None
                sqli_det  = SQLiDetector(client)      if self._flags.get("run_sqli")       else None
                blind_det = BlindSQLiDetector(client) if self._flags.get("run_blind_sqli") else None
                redir_det = RedirectDetector(client)  if self._flags.get("run_redirects")  else None
                idor_det  = IDORDetector(client)      if self._flags.get("run_idor")       else None

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

                        await progress.put({"type": "progress", "data": {
                            "phase": "fuzzing",
                            "current": idx + 1,
                            "total": len(all_vectors),
                            "message": f"[{idx+1}/{len(all_vectors)}] {vector.method} {vector.url} [{vector.param_name}]",
                            "new_findings": len(local_findings),
                        }})
                        return local_findings

                batch_results = await asyncio.gather(
                    *[test_one(i, v) for i, v in enumerate(all_vectors)],
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
            input_vectors = len(all_vectors),
            api_endpoints = len(api_vectors),
            findings      = [f.to_dict() for f in findings],
            errors        = errors,
        )


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
