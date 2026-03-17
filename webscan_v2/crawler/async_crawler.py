"""
crawler/async_crawler.py — Async BFS web crawler using httpx.

Key improvements over v1:
  - httpx.AsyncClient replaces requests (async I/O, HTTP/2 support)
  - asyncio.Semaphore limits concurrent connections
  - Response body stored for later detection passes
  - JavaScript-hinted URL extraction (href in <script> src, data-url attrs)
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse

import httpx
from bs4 import BeautifulSoup

from config import DEFAULT_TIMEOUT, DEFAULT_DELAY, USER_AGENT, get_browser_headers

log = logging.getLogger(__name__)

MAX_CONCURRENCY = 10   # simultaneous in-flight requests


@dataclass
class FormInput:
    name: str
    input_type: str
    value: str = ""
    required: bool = False


@dataclass
class DiscoveredForm:
    action: str
    method: str
    inputs: list[FormInput] = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"


@dataclass
class PageResult:
    url: str
    status_code: int
    content_type: str
    headers: dict
    body: str = ""                          # raw response body (NEW in v2)
    links: list[str] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)
    query_params: dict = field(default_factory=dict)
    depth: int = 0
    response_time_ms: float = 0.0          # NEW: for baseline timing
    error: Optional[str] = None


class AsyncCrawler:
    def __init__(
        self,
        root_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        delay: float = DEFAULT_DELAY,
        timeout: int = DEFAULT_TIMEOUT,
    ):
        parsed = urlparse(root_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"root_url must include scheme and host: {root_url!r}")

        self.root_url  = root_url
        self.origin    = f"{parsed.scheme}://{parsed.netloc}"
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.delay     = delay
        self.timeout   = timeout
        self._visited: set[str] = set()
        self.results: list[PageResult] = []
        self._sem = asyncio.Semaphore(MAX_CONCURRENCY)

    async def crawl(self, on_page=None) -> list[PageResult]:
        """
        BFS crawl. `on_page` is an optional async callback(PageResult) for
        live progress reporting.
        """
        limits  = httpx.Limits(max_connections=MAX_CONCURRENCY, max_keepalive_connections=10)

        async with httpx.AsyncClient(
            headers=get_browser_headers(self.root_url),
            timeout=self.timeout,
            verify=False,
            follow_redirects=True,
            limits=limits,
        ) as client:
            queue: list[tuple[str, int]] = [(self.root_url, 0)]

            while queue and len(self._visited) < self.max_pages:
                # Process up to MAX_CONCURRENCY pages at once
                batch, queue = queue[:MAX_CONCURRENCY], queue[MAX_CONCURRENCY:]

                tasks = []
                for url, depth in batch:
                    norm = self._normalise(url)
                    if norm in self._visited or not self._in_scope(norm):
                        continue
                    self._visited.add(norm)
                    tasks.append(self._fetch(client, norm, depth))

                if not tasks:
                    continue

                pages = await asyncio.gather(*tasks, return_exceptions=True)

                for page in pages:
                    if isinstance(page, Exception):
                        log.warning("Fetch error: %s", page)
                        continue
                    self.results.append(page)
                    if on_page:
                        await on_page(page)
                    if page.error or page.depth >= self.max_depth:
                        continue
                    for link in page.links:
                        norm_link = self._normalise(link)
                        if norm_link not in self._visited and self._in_scope(norm_link):
                            queue.append((norm_link, page.depth + 1))

                if self.delay > 0:
                    await asyncio.sleep(self.delay)

        log.info("Crawl done — %d pages", len(self.results))
        return self.results

    async def _fetch(self, client: httpx.AsyncClient, url: str, depth: int) -> PageResult:
        async with self._sem:
            try:
                t0   = time.monotonic()
                resp = await client.get(url)
                ms   = (time.monotonic() - t0) * 1000
                ct   = resp.headers.get("content-type", "")
                body = resp.text if "html" in ct or "json" in ct or "text" in ct else ""
                soup = BeautifulSoup(body, "lxml") if "html" in ct else None

                return PageResult(
                    url=url,
                    status_code=resp.status_code,
                    content_type=ct,
                    headers=dict(resp.headers),
                    body=body,
                    links=self._extract_links(soup, url) if soup else [],
                    forms=self._extract_forms(soup, url) if soup else [],
                    query_params=dict(parse_qs(urlparse(url).query)),
                    depth=depth,
                    response_time_ms=ms,
                )
            except Exception as exc:
                return PageResult(
                    url=url, status_code=0, content_type="", headers={},
                    depth=depth, error=str(exc),
                )

    def _extract_links(self, soup: BeautifulSoup, base: str) -> list[str]:
        links: set[str] = set()
        for tag in soup.find_all(["a", "link"], href=True):
            href = tag["href"].strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            links.add(self._strip_fragment(urljoin(base, href)))

        # Also extract src attrs that look like page URLs (not .js/.css)
        for tag in soup.find_all(True, {"data-url": True, "data-href": True}):
            for attr in ("data-url", "data-href"):
                val = tag.get(attr, "").strip()
                if val.startswith("/") or val.startswith(self.origin):
                    links.add(self._strip_fragment(urljoin(base, val)))

        # Form actions
        for form in soup.find_all("form", action=True):
            action = form.get("action", "").strip()
            if action and not action.startswith("javascript:"):
                links.add(self._strip_fragment(urljoin(base, action)))

        return list(links)

    def _extract_forms(self, soup: BeautifulSoup, base: str) -> list[DiscoveredForm]:
        forms = []
        for form_tag in soup.find_all("form"):
            action  = urljoin(base, form_tag.get("action", base))
            method  = (form_tag.get("method", "GET") or "GET").upper()
            enctype = form_tag.get("enctype", "application/x-www-form-urlencoded")
            inputs  = []
            for inp in form_tag.find_all(["input", "textarea", "select"]):
                name = inp.get("name") or inp.get("id") or ""
                if not name:
                    continue
                inputs.append(FormInput(
                    name=name,
                    input_type=inp.get("type", "text").lower(),
                    value=inp.get("value", ""),
                    required=inp.has_attr("required"),
                ))
            forms.append(DiscoveredForm(action=action, method=method,
                                        inputs=inputs, enctype=enctype))
        return forms

    def _in_scope(self, url: str) -> bool:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}" == self.origin

    def _normalise(self, url: str) -> str:
        p = urlparse(urljoin(self.origin, url))
        return urlunparse((p.scheme.lower(), p.netloc.lower(),
                           p.path, p.params, p.query, ""))

    @staticmethod
    def _strip_fragment(url: str) -> str:
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))
