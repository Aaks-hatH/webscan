"""
discovery/js_extractor.py

Extracts API endpoint patterns from JavaScript bundles loaded by the frontend.

This is how we discover the full API surface of SPAs like PlanIt — the
crawler sees zero API links in HTML, but the JS bundles contain every
fetch/axios call the app makes.

Extraction strategy:
  1. Crawl the HTML pages and collect all <script src="..."> URLs.
  2. Fetch each JS bundle (typically /assets/index-[hash].js etc).
  3. Run regex patterns against the bundle text to find:
       - axios/fetch calls:   axios.get('/api/events'), fetch(`/api/...`)
       - Route constants:     const API_URL = '/api/...', apiPaths.events
       - Template literals:   `/api/events/${id}/participants`
       - String patterns:     '/api/', 'http://', 'https://'
  4. Normalise found paths into InputVector objects for the scanner.

Limitations:
  - Minified bundles collapse variable names, so template literal extraction
    is best-effort. We replace ${...} with a placeholder.
  - We don't execute JS, so dynamic route construction is missed.
  - Source maps (if present) would give perfect results but are rarely
    deployed to production.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from discovery.input_discovery import InputVector

log = logging.getLogger(__name__)

# ── Regex patterns for API endpoint extraction ────────────────────────────────

# Matches quoted strings containing /api/
_QUOTED_API = re.compile(
    r"""["'`](/api/[^"'`\s]{1,200})["'`]""",
    re.MULTILINE,
)

# Template literals: `/api/events/${eventId}/tasks`
_TEMPLATE_API = re.compile(
    r"""`(/api/[^`\n]{1,200})`""",
    re.MULTILINE,
)

# axios.get/post/put/delete/patch(...)
_AXIOS_CALL = re.compile(
    r"""axios\s*\.\s*(?:get|post|put|patch|delete|head)\s*\(\s*["'`]([^"'`\n]+)["'`]""",
    re.IGNORECASE | re.MULTILINE,
)

# fetch("...")
_FETCH_CALL = re.compile(
    r"""fetch\s*\(\s*["'`]([^"'`\n]+)["'`]""",
    re.IGNORECASE | re.MULTILINE,
)

# HTTP method hints from nearby code: .post(url), router.get(...)
_METHOD_HINT = re.compile(
    r"""\.(get|post|put|patch|delete)\s*\(\s*["'`](/api/[^"'`\n]+)["'`]""",
    re.IGNORECASE | re.MULTILINE,
)

# Common variable names holding base URLs
_BASE_URL_VAR = re.compile(
    r"""(?:API_URL|BASE_URL|apiBase|baseURL|BASE)\s*=\s*["'`]([^"'`\s]{5,100})["'`]""",
    re.IGNORECASE | re.MULTILINE,
)

# Template literal with variable: `/api/events/${x}/tasks` → /api/events/{id}/tasks
_TEMPLATE_VAR = re.compile(r'\$\{[^}]{1,40}\}')


@dataclass
class DiscoveredAPIEndpoint:
    path:         str          # e.g. /api/events/{id}/tasks
    method:       str          # GET | POST | PUT | DELETE | PATCH | UNKNOWN
    source_file:  str          # which JS bundle
    has_path_var: bool         # contains {id} placeholder
    raw:          str          # original match


@dataclass
class JSExtractResult:
    endpoints:   list[DiscoveredAPIEndpoint] = field(default_factory=list)
    base_urls:   list[str]                   = field(default_factory=list)
    js_files:    list[str]                   = field(default_factory=list)
    errors:      list[str]                   = field(default_factory=list)


class JSEndpointExtractor:
    """
    Fetches JS bundles from a target origin and extracts API endpoint paths.

    Usage:
        extractor = JSEndpointExtractor(client, origin="https://app.example.com")
        result    = await extractor.run(html_pages)
        vectors   = extractor.to_input_vectors(result, origin)
    """

    def __init__(self, client: httpx.AsyncClient, origin: str):
        self.client = client
        self.origin = origin

    async def run(self, pages: list) -> JSExtractResult:
        """
        pages: list of PageResult from the crawler (we need their bodies and URLs).
        """
        result = JSExtractResult()

        # Step 1: Collect JS bundle URLs from all crawled pages
        js_urls: set[str] = set()
        for page in pages:
            if not page.body:
                continue
            try:
                soup  = BeautifulSoup(page.body, "lxml")
                for tag in soup.find_all("script", src=True):
                    src = tag["src"].strip()
                    if not src or src.startswith("data:"):
                        continue
                    full = urljoin(page.url, src)
                    if urlparse(full).netloc == urlparse(self.origin).netloc:
                        js_urls.add(full)
            except Exception:
                pass

        # Also probe common bundle locations if we didn't find many scripts
        if len(js_urls) < 2:
            for probe_path in ["/assets/index.js", "/static/js/main.js",
                               "/app.js", "/bundle.js"]:
                js_urls.add(self.origin + probe_path)

        result.js_files = list(js_urls)
        log.info("JS extractor: found %d script URLs", len(js_urls))

        # Step 2: Fetch bundles concurrently
        sem   = asyncio.Semaphore(5)
        tasks = [self._fetch_and_extract(url, result, sem) for url in js_urls]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Step 3: Deduplicate endpoints
        seen: set[tuple] = set()
        unique = []
        for ep in result.endpoints:
            key = (ep.path.lower(), ep.method)
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        result.endpoints = unique

        log.info("JS extractor: discovered %d unique API endpoints", len(unique))
        return result

    async def _fetch_and_extract(
        self,
        url: str,
        result: JSExtractResult,
        sem: asyncio.Semaphore,
    ) -> None:
        async with sem:
            try:
                resp = await self.client.get(url, timeout=15)
                if resp.status_code != 200:
                    return
                ct = resp.headers.get("content-type", "")
                if "javascript" not in ct and "text" not in ct:
                    return
                body = resp.text
            except Exception as exc:
                result.errors.append(f"JS fetch failed ({url}): {exc}")
                return

        # Extract base URL variables
        for m in _BASE_URL_VAR.finditer(body):
            result.base_urls.append(m.group(1))

        # Extract endpoints with method hints first (most reliable)
        for m in _METHOD_HINT.finditer(body):
            method, path = m.group(1).upper(), m.group(2)
            ep = _make_endpoint(path, method, url)
            if ep:
                result.endpoints.append(ep)

        # axios calls
        for m in _AXIOS_CALL.finditer(body):
            # Try to find the method from the call itself
            call_text = body[max(0, m.start()-10):m.start()+5].lower()
            method = "GET"
            for meth in ["post", "put", "patch", "delete"]:
                if meth in call_text:
                    method = meth.upper()
                    break
            ep = _make_endpoint(m.group(1), method, url)
            if ep:
                result.endpoints.append(ep)

        # fetch() calls
        for m in _FETCH_CALL.finditer(body):
            ep = _make_endpoint(m.group(1), "UNKNOWN", url)
            if ep:
                result.endpoints.append(ep)

        # Quoted /api/ strings
        for m in _QUOTED_API.finditer(body):
            ep = _make_endpoint(m.group(1), "UNKNOWN", url)
            if ep:
                result.endpoints.append(ep)

        # Template literals
        for m in _TEMPLATE_API.finditer(body):
            raw  = m.group(1)
            norm = _TEMPLATE_VAR.sub("{id}", raw)
            ep   = _make_endpoint(norm, "UNKNOWN", url)
            if ep:
                result.endpoints.append(ep)

    def to_input_vectors(self, result: JSExtractResult) -> list[InputVector]:
        """Convert discovered endpoints to InputVector objects for the scanner."""
        vectors = []
        for ep in result.endpoints:
            full_url = urljoin(self.origin, ep.path)

            # If path has {id} placeholder, add as a path-param vector
            if ep.has_path_var:
                vectors.append(InputVector(
                    url=full_url,
                    method=ep.method if ep.method != "UNKNOWN" else "GET",
                    param_name="<path-id>",
                    param_type="path",
                    example_value="1",
                    source_page=ep.source_file,
                ))
            else:
                vectors.append(InputVector(
                    url=full_url,
                    method=ep.method if ep.method != "UNKNOWN" else "GET",
                    param_name="<api-endpoint>",
                    param_type="json",
                    source_page=ep.source_file,
                ))

        return vectors


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_endpoint(
    raw_path: str,
    method: str,
    source: str,
) -> DiscoveredAPIEndpoint | None:
    """Validate and normalise a raw path string into an endpoint."""
    path = raw_path.strip()

    # Must start with / or be a relative API path
    if not path.startswith("/"):
        if path.startswith("http"):
            parsed = urlparse(path)
            path   = parsed.path
        else:
            return None

    # Must contain /api/ or look like a REST endpoint
    if "/api/" not in path and not _looks_like_rest(path):
        return None

    # Skip obviously non-endpoint strings
    if any(skip in path for skip in [".js", ".css", ".png", ".svg", ".ico", ".map"]):
        return None

    # Normalise template variables
    has_var = "{id}" in path
    path    = _TEMPLATE_VAR.sub("{id}", path)

    # Truncate very long paths (noise)
    if len(path) > 150:
        return None

    return DiscoveredAPIEndpoint(
        path=path,
        method=method,
        source_file=source,
        has_path_var=has_var or bool(re.search(r'\{[^}]+\}|:\w+', path)),
        raw=raw_path,
    )


def _looks_like_rest(path: str) -> bool:
    """Heuristic: does this path look like a REST endpoint?"""
    segments = [s for s in path.split("/") if s]
    return (
        len(segments) >= 2
        and all(c.isalnum() or c in "-_{}:" for s in segments for c in s)
        and not path.endswith((".html", ".txt", ".xml"))
    )
