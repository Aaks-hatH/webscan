"""
detection/dom_xss_detector.py — Static DOM XSS detector.

Analyses crawled page bodies for JavaScript patterns that are commonly
associated with DOM-based XSS sinks and sources, without making additional
HTTP requests.

Checks for:
- Dangerous sinks: document.write, innerHTML, outerHTML, insertAdjacentHTML,
  eval, setTimeout/setInterval with string args, location.href/assign/replace
- Dangerous sources flowing into sinks: location.hash, location.search,
  location.href, document.referrer, document.URL, window.name
- jQuery dangerous helpers: $().html(), $().append() with tainted data
"""

import re
import logging
from dataclasses import dataclass

from crawler.async_crawler import PageResult
from detection.finding import Finding

log = logging.getLogger(__name__)

# ── Patterns ──────────────────────────────────────────────────────────────

# Sinks — places where attacker-controlled data can cause script execution
_SINK_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    (
        "document.write sink",
        "document.write() or document.writeln() called — if data derives from a "
        "URL parameter or user-controlled source this is a DOM XSS sink.",
        re.compile(r"document\.write(?:ln)?\s*\(", re.IGNORECASE),
    ),
    (
        "innerHTML / outerHTML assignment",
        "innerHTML or outerHTML assignment found — if the right-hand side includes "
        "URL-derived data an attacker can inject arbitrary HTML/script.",
        re.compile(r"\.(?:inner|outer)HTML\s*[+]?=", re.IGNORECASE),
    ),
    (
        "insertAdjacentHTML sink",
        "insertAdjacentHTML() can inject arbitrary HTML when the content argument "
        "originates from a user-controlled source.",
        re.compile(r"\.insertAdjacentHTML\s*\(", re.IGNORECASE),
    ),
    (
        "eval() sink",
        "eval() executes its string argument as JavaScript. If the argument contains "
        "any user-controlled data this is a direct code injection vector.",
        re.compile(r"\beval\s*\(", re.IGNORECASE),
    ),
    (
        "setTimeout/setInterval with string argument",
        "setTimeout/setInterval called with a string literal acts like eval() and "
        "can execute attacker-controlled code.",
        re.compile(
            r"\b(?:setTimeout|setInterval)\s*\(\s*['\"`]",
            re.IGNORECASE,
        ),
    ),
    (
        "location.href / location.assign / location.replace assignment",
        "Assigning to location.href, location.assign(), or location.replace() with "
        "unsanitised input enables open-redirect and javascript: URI execution.",
        re.compile(
            r"location\.(?:href\s*[+]?=|assign\s*\(|replace\s*\()",
            re.IGNORECASE,
        ),
    ),
    (
        "jQuery .html() / .append() sink",
        "jQuery .html() and .append() parse their argument as HTML. If the argument "
        "contains URL-derived data an attacker can inject arbitrary script.",
        re.compile(r"\$\([^)]*\)\s*\.(?:html|append)\s*\(", re.IGNORECASE),
    ),
]

# Sources — tainted data origins commonly found alongside sinks
_SOURCE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("location.hash",     re.compile(r"\blocation\.hash\b",     re.IGNORECASE)),
    ("location.search",   re.compile(r"\blocation\.search\b",   re.IGNORECASE)),
    ("location.href",     re.compile(r"\blocation\.href\b",     re.IGNORECASE)),
    ("document.referrer", re.compile(r"\bdocument\.referrer\b", re.IGNORECASE)),
    ("document.URL",      re.compile(r"\bdocument\.URL\b",      re.IGNORECASE)),
    ("window.name",       re.compile(r"\bwindow\.name\b",       re.IGNORECASE)),
]

# Inline script extraction
_SCRIPT_RE = re.compile(
    r"<script(?:\s[^>]*)?>(.+?)</script>",
    re.DOTALL | re.IGNORECASE,
)


def _extract_scripts(html: str) -> list[str]:
    """Return all inline <script> blocks from the HTML."""
    return _SCRIPT_RE.findall(html)


def _snippet(script: str, pattern: re.Pattern, ctx: int = 160) -> str:
    m = pattern.search(script)
    if not m:
        return ""
    start = max(0, m.start() - ctx // 2)
    end   = min(len(script), m.end() + ctx // 2)
    return "…" + script[start:end].strip() + "…"


class DOMXSSDetector:
    """
    Passive DOM XSS detector.

    Analyses the raw HTML bodies collected by the crawler and emits a finding
    for every dangerous sink pattern discovered.  If a known taint source also
    appears in the same script block the severity is raised to HIGH; otherwise
    it defaults to MEDIUM (the pattern is present but flow is uncertain).
    """

    def check_page(self, page: PageResult) -> list[Finding]:
        if not page.body:
            return []
        if "html" not in page.content_type.lower():
            return []

        scripts = _extract_scripts(page.body)
        if not scripts:
            return []

        findings: list[Finding] = []
        seen: set[str] = set()

        for script in scripts:
            for sink_label, sink_desc, sink_re in _SINK_PATTERNS:
                if not sink_re.search(script):
                    continue

                # Check whether a taint source is also in the same block
                sources_found = [
                    name for name, src_re in _SOURCE_PATTERNS
                    if src_re.search(script)
                ]

                severity  = "HIGH" if sources_found else "MEDIUM"
                dedup_key = f"{page.url}|{sink_label}"
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                source_note = (
                    f" Taint sources present in the same script block: "
                    f"{', '.join(sources_found)}."
                    if sources_found
                    else " No obvious taint source detected in this block — "
                         "manual review recommended."
                )

                findings.append(Finding(
                    vuln_type="DOM-Based XSS Indicator",
                    severity=severity,
                    url=page.url,
                    param="(inline script)",
                    method="GET",
                    request_example=f"GET {page.url}",
                    response_indicator=f"Sink pattern matched: {sink_label}",
                    evidence_snippet=_snippet(script, sink_re),
                    description=(
                        f"A potentially dangerous JavaScript sink was found in an "
                        f"inline script on {page.url!r}. {sink_desc}{source_note}"
                    ),
                    mitigation=(
                        "Avoid passing URL-derived or user-controlled data directly "
                        "to HTML sinks. Use textContent instead of innerHTML where "
                        "possible. Validate and sanitise all data before passing to "
                        "eval(), document.write(), or location properties. Apply a "
                        "strict Content-Security-Policy that disallows unsafe-eval "
                        "and unsafe-inline."
                    ),
                    cwe="CWE-79",
                    confidence="MEDIUM" if not sources_found else "HIGH",
                ))

        return findings
