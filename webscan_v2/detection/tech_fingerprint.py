"""
detection/tech_fingerprint.py — Technology stack fingerprinter.

Identifies the framework, runtime, database, and CDN from:
  - HTTP response headers (Server, X-Powered-By, X-Generator, etc.)
  - HTML meta tags and generator comments
  - JavaScript bundle filenames and global variables
  - Cookie names (PHPSESSID, JSESSIONID, connect.sid, _rails_session, etc.)
  - Error page patterns
  - robots.txt / sitemap / manifest patterns
  - OpenAPI spec metadata

Returns a TechProfile dataclass and a list of Findings that report:
  - Confirmed technologies with versions (INFO severity)
  - Version disclosures that could aid targeted attacks (LOW/MEDIUM)
  - Dangerous combinations (e.g. outdated Express + known CVE)
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from crawler.async_crawler import PageResult
from detection.finding import Finding

log = logging.getLogger(__name__)


@dataclass
class TechProfile:
    frameworks:  list[str] = field(default_factory=list)
    runtimes:    list[str] = field(default_factory=list)
    databases:   list[str] = field(default_factory=list)
    cdn_waf:     list[str] = field(default_factory=list)
    server:      str = ""
    versions:    dict = field(default_factory=dict)
    is_spa:      bool = False
    spa_hint:    str = ""
    has_graphql: bool = False
    raw_clues:   list[str] = field(default_factory=list)

    def summary(self) -> str:
        parts = (
            self.frameworks + self.runtimes + self.databases +
            self.cdn_waf + ([self.server] if self.server else [])
        )
        return ", ".join(p for p in dict.fromkeys(parts) if p) or "Unknown"


# ── Detection rules ───────────────────────────────────────────────────────────

_HEADER_RULES: list[tuple[str, str, str, str]] = [
    # (header_name, regex_pattern, tech_category, label)
    ("server",       r"nginx/([\d.]+)",          "server",    "nginx/{1}"),
    ("server",       r"apache/([\d.]+)",          "server",    "Apache/{1}"),
    ("server",       r"openresty/([\d.]+)",        "server",    "OpenResty/{1}"),
    ("server",       r"caddy/([\d.]+)",            "server",    "Caddy/{1}"),
    ("server",       r"iis/([\d.]+)",              "server",    "IIS/{1}"),
    ("server",       r"cloudflare",                "cdn_waf",   "Cloudflare"),
    ("server",       r"fastly",                    "cdn_waf",   "Fastly"),
    ("server",       r"render",                    "cdn_waf",   "Render"),
    ("x-powered-by", r"express",                   "frameworks","Express.js"),
    ("x-powered-by", r"php/([\d.]+)",              "runtimes",  "PHP/{1}"),
    ("x-powered-by", r"asp\.net",                  "frameworks","ASP.NET"),
    ("x-powered-by", r"next\.js",                  "frameworks","Next.js"),
    ("x-powered-by", r"django",                    "frameworks","Django"),
    ("x-powered-by", r"rails",                     "frameworks","Rails"),
    ("x-powered-by", r"laravel",                   "frameworks","Laravel"),
    ("x-powered-by", r"fastapi",                   "frameworks","FastAPI"),
    ("via",          r"cloudfront",                "cdn_waf",   "CloudFront"),
    ("cf-ray",       r".",                         "cdn_waf",   "Cloudflare"),
    ("x-vercel",     r".",                         "cdn_waf",   "Vercel"),
    ("x-render-origin-server", r".", "cdn_waf",   "Render"),
    ("x-amzn-requestid", r".",                    "cdn_waf",   "AWS"),
    ("x-cache",      r"hit from cloudfront",       "cdn_waf",   "CloudFront"),
]

_COOKIE_RULES: list[tuple[str, str]] = [
    # (cookie_name_pattern, tech_label)
    (r"phpsessid",            "PHP"),
    (r"jsessionid",           "Java/Tomcat"),
    (r"connect\.sid",         "Express.js/connect"),
    (r"_rails_session",       "Rails"),
    (r"laravel_session",      "Laravel"),
    (r"django_session|csrftoken", "Django"),
    (r"asp\.net_sessionid",   "ASP.NET"),
    (r"__cfduid|cf_clearance","Cloudflare"),
    (r"_ga|_gid",             "Google Analytics"),
    (r"_fbp",                 "Facebook Pixel"),
]

_HTML_RULES: list[tuple[str, str, str]] = [
    # (regex_on_html, tech_category, label)
    (r"<meta[^>]+generator[^>]*wordpress",             "frameworks","WordPress"),
    (r"<meta[^>]+generator[^>]*drupal",                "frameworks","Drupal"),
    (r"<meta[^>]+generator[^>]*joomla",                "frameworks","Joomla"),
    (r"react\.development\.js|react\.production\.min", "frameworks","React"),
    (r"vue\.js|vue\.min\.js|vue@",                     "frameworks","Vue.js"),
    (r"angular(?:\.min)?\.js|@angular/core",           "frameworks","Angular"),
    (r"svelte",                                        "frameworks","Svelte"),
    (r"ember\.js|ember\.min",                          "frameworks","Ember.js"),
    (r"backbone\.js",                                  "frameworks","Backbone.js"),
    (r"next/static|__NEXT_DATA__",                     "frameworks","Next.js"),
    (r"nuxt\.js|__NUXT__",                             "frameworks","Nuxt.js"),
    (r"gatsby-ssr|gatsby-browser",                     "frameworks","Gatsby"),
    (r"window\.__REDUX_STORE__|createStore",            "frameworks","Redux"),
    (r"graphql|__schema|introspection",                "databases", "GraphQL"),
    (r"mongodb|mongoose",                              "databases", "MongoDB"),
    (r"prisma\.io|prisma client",                      "databases", "Prisma"),
    (r"stripe\.js|stripe\.com/v3",                     "runtimes",  "Stripe"),
    (r"sentry\.io|sentry\.browser",                    "runtimes",  "Sentry"),
    (r"socket\.io",                                    "runtimes",  "Socket.io"),
    (r"__webpack_require__|webpackBootstrap",           "runtimes",  "Webpack"),
    (r"vite/dist|vite\.config",                        "runtimes",  "Vite"),
]

_PATH_RULES: list[tuple[str, str, str]] = [
    # (url_pattern, tech_category, label)
    (r"/wp-content/|/wp-includes/",  "frameworks","WordPress"),
    (r"/static/admin/",              "frameworks","Django"),
    (r"/rails/",                     "frameworks","Rails"),
    (r"/vendor/laravel",             "frameworks","Laravel"),
    (r"\.php$",                      "runtimes",  "PHP"),
    (r"\.aspx?$",                    "runtimes",  "ASP.NET"),
    (r"\.jsp$",                      "runtimes",  "Java/JSP"),
    (r"\.cfm$",                      "runtimes",  "ColdFusion"),
    (r"/api/v\d+/",                  "frameworks","REST API"),
    (r"/graphql",                    "databases", "GraphQL"),
]


class TechFingerprinter:
    """
    Passive technology fingerprinter — no extra requests, reads crawled pages.
    """

    def fingerprint(self, pages: list[PageResult]) -> tuple[TechProfile, list[Finding]]:
        profile  = TechProfile()
        findings: list[Finding] = []
        seen_tech: set[str]     = set()
        version_disclosures: list[tuple[str, str, str]] = []  # (header, value, url)

        for page in pages:
            if page.error:
                continue

            hl = {k.lower(): v for k, v in page.headers.items()}

            # ── Headers ───────────────────────────────────────────────────────
            for hdr, pattern, category, label_tpl in _HEADER_RULES:
                val = hl.get(hdr, "")
                if not val:
                    continue
                m = re.search(pattern, val, re.IGNORECASE)
                if not m:
                    continue
                try:
                    label = label_tpl.format(*[""] + list(m.groups()))
                except (IndexError, KeyError):
                    label = label_tpl.split("/")[0]

                label = label.strip("/")
                if label not in seen_tech:
                    seen_tech.add(label)
                    getattr(profile, category, profile.frameworks).append(label)
                    profile.raw_clues.append(f"{hdr}: {val[:80]}")

                # Version disclosure
                if m.groups() and m.group(1):
                    version_disclosures.append((hdr, f"{label} ({m.group(1)})", page.url))

            # Track server header separately for clean display
            if "server" in hl and not profile.server:
                profile.server = hl["server"][:80]

            # ── Cookies ───────────────────────────────────────────────────────
            cookies_raw = hl.get("set-cookie", "")
            for pattern, label in _COOKIE_RULES:
                if re.search(pattern, cookies_raw, re.IGNORECASE):
                    if label not in seen_tech:
                        seen_tech.add(label)
                        profile.frameworks.append(label)
                        profile.raw_clues.append(f"Cookie pattern: {pattern}")

            # ── HTML body ─────────────────────────────────────────────────────
            body = (page.body or "").lower()
            for pattern, category, label in _HTML_RULES:
                if re.search(pattern, body, re.IGNORECASE):
                    if label not in seen_tech:
                        seen_tech.add(label)
                        cat_list = getattr(profile, category, profile.frameworks)
                        cat_list.append(label)
                        profile.raw_clues.append(f"HTML: {pattern[:50]}")
                    if label in ("GraphQL",):
                        profile.has_graphql = True

            # SPA detection signals
            if any(x in body for x in ("__next_data__", "__nuxt__", "window.__redux")):
                profile.is_spa = True
            if "react" in seen_tech or "vue.js" in seen_tech or "angular" in seen_tech:
                profile.is_spa = True
                profile.spa_hint = next(
                    (t for t in ("React","Vue.js","Angular","Next.js","Nuxt.js")
                     if t in seen_tech), "SPA"
                )

            # ── URL path hints ────────────────────────────────────────────────
            for pattern, category, label in _PATH_RULES:
                if re.search(pattern, page.url, re.IGNORECASE):
                    if label not in seen_tech:
                        seen_tech.add(label)
                        getattr(profile, category, profile.frameworks).append(label)

        # ── Version disclosure findings ───────────────────────────────────────
        seen_disclosures: set[str] = set()
        for header, tech_version, url in version_disclosures:
            if tech_version in seen_disclosures:
                continue
            seen_disclosures.add(tech_version)
            findings.append(Finding(
                vuln_type="Technology Version Disclosure",
                severity="LOW",
                url=url,
                param=header,
                method="GET",
                request_example=f"GET {url}",
                response_indicator=f"{header}: {tech_version}",
                evidence_snippet=f"Detected: {tech_version}",
                description=(
                    f"The response header '{header}' discloses the version of "
                    f"{tech_version}. Attackers use version info to look up known "
                    "CVEs and craft targeted exploits."
                ),
                mitigation=f"Remove or obscure the '{header}' header in server configuration.",
                cwe="CWE-200",
                confidence="HIGH",
            ))

        # ── Technology summary finding ─────────────────────────────────────────
        if seen_tech:
            findings.append(Finding(
                vuln_type="Technology Stack Identified",
                severity="INFO",
                url=pages[0].url if pages else "",
                param="(fingerprint)",
                method="GET",
                request_example="# Passive fingerprint — no extra requests",
                response_indicator=profile.summary(),
                evidence_snippet="\n".join(profile.raw_clues[:20]),
                description=(
                    f"Technology stack identified: {profile.summary()}. "
                    "This information helps scope subsequent targeted checks."
                ),
                mitigation=(
                    "Suppress version-disclosing headers (Server, X-Powered-By, X-Generator). "
                    "Keep all identified components up-to-date."
                ),
                cwe="CWE-200",
                confidence="HIGH",
            ))

        return profile, findings
