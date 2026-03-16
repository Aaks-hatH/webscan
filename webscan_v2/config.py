"""
webscan_v2/config.py — All probes, patterns, and scan profile definitions.
"""

# ── Request settings ──────────────────────────────────────────────────────────
DEFAULT_TIMEOUT   = 10
DEFAULT_DELAY     = 0.3
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_PAGES = 100
USER_AGENT = (
    "WebScan-Educational/2.0 "
    "(authorized security testing; "
    "github.com/your-org/webscan)"
)

# ── XSS probes ────────────────────────────────────────────────────────────────
XSS_PROBES = [
    '<wbr id="xss-probe-1">',
    '"xss-probe-2"',
    "xss-probe-3'",
    "<img/src=x id=xss-probe-4>",
]
STORED_XSS_PROBE_TEMPLATE = 'wscan-stored-{uid}'   # uid = 8-char hex

# ── SQLi ──────────────────────────────────────────────────────────────────────
SQLI_PROBES = ["'", "1 AND 1=1", "1 OR 1=1"]

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg::syntaxerror",
    "sqlite3::operationalerror",
    "microsoft ole db provider for sql server",
    "odbc microsoft access driver",
    "ora-01756",
    "db2 sql error",
]

# ── Blind SQLi time-based payloads ────────────────────────────────────────────
# Each payload targets a different DB backend. Delay = 3 seconds.
BLIND_SQLI_PAYLOADS = [
    ("'; WAITFOR DELAY '0:0:3'--",              "MSSQL"),
    ("'; SELECT SLEEP(3)--",                    "MySQL"),
    ("'; SELECT pg_sleep(3)--",                 "PostgreSQL"),
    ("1'; WAITFOR DELAY '0:0:3'--",             "MSSQL (numeric)"),
    ("1 AND SLEEP(3)",                          "MySQL (no quote)"),
    ("1) OR SLEEP(3)--",                        "MySQL (bracket)"),
]
BLIND_SQLI_DELAY_THRESHOLD = 2.5   # seconds above baseline

# ── Security headers ──────────────────────────────────────────────────────────
REQUIRED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Absent CSP allows inline script execution, increasing XSS impact.",
        "mitigation": "Add Content-Security-Policy: default-src 'self' and expand as needed.",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Missing X-Frame-Options enables clickjacking.",
        "mitigation": "Set X-Frame-Options: DENY or SAMEORIGIN.",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": "Absent header allows MIME-type sniffing.",
        "mitigation": "Set X-Content-Type-Options: nosniff.",
    },
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HSTS absent; plain-HTTP connections may be accepted.",
        "mitigation": "Set Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "No Referrer-Policy; URLs may leak in Referer header.",
        "mitigation": "Set Referrer-Policy: no-referrer or strict-origin-when-cross-origin.",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "No Permissions-Policy restricts browser API access.",
        "mitigation": "Add Permissions-Policy to disable unused APIs.",
    },
}

DANGEROUS_HEADERS = {
    "Server":           {"severity": "INFO", "description": "Server version disclosed.", "mitigation": "Suppress or genericise the Server header."},
    "X-Powered-By":     {"severity": "INFO", "description": "Technology stack disclosed.", "mitigation": "Remove X-Powered-By header."},
    "X-AspNet-Version": {"severity": "LOW",  "description": "ASP.NET version disclosed.", "mitigation": "Remove X-AspNet-Version in IIS config."},
}

# ── Open redirect ─────────────────────────────────────────────────────────────
REDIRECT_PAYLOADS = ["https://evil.example.com", "//evil.example.com"]
REDIRECT_PARAMS   = [
    "redirect", "redirect_to", "redirect_url", "url", "next",
    "return", "return_url", "goto", "dest", "destination",
    "redir", "r", "out", "jump", "link", "target",
]

# ── Sensitive paths ───────────────────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.htaccess", "/.htpasswd", "/wp-config.php", "/config.php",
    "/config.yml", "/config.yaml", "/config.json", "/settings.py",
    "/local_settings.py", "/database.yml", "/package.json",
    "/web.config", "/phpinfo.php", "/info.php", "/test.php",
    "/backup.sql", "/dump.sql", "/db.sql", "/robots.txt",
    "/server-status", "/.DS_Store", "/.svn/entries",
    "/.bash_history", "/id_rsa", "/id_dsa",
]

# ── Info leak patterns ────────────────────────────────────────────────────────
LEAK_PATTERNS = {
    "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
    "Generic API Key":   r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?[0-9a-zA-Z\-_]{16,}",
    "Private Key":       r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Password in HTML":  r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",
    "JWT Token":         r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "Basic Auth in URL": r"https?://[^:@/\n]+:[^@/\n]+@",
    "Internal IP":       r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    "Stack Trace (Python)": r"Traceback \(most recent call last\)",
    "Stack Trace (PHP)": r"(Fatal error|Warning):\s+.+\sin\s+.+\.php\s+on\s+line\s+\d+",
    "Stack Trace (Java)": r"at [a-zA-Z_$][a-zA-Z0-9_$.]*\([A-Za-z0-9_.]+:\d+\)",
}

# ── CSRF token field names ────────────────────────────────────────────────────
CSRF_TOKEN_NAMES = {
    "csrf", "_csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
    "authenticity_token", "__requestverificationtoken", "xsrf",
    "_xsrf", "xsrf_token", "_token", "token",
}

# ── Scan profiles ─────────────────────────────────────────────────────────────
PROFILES: dict[str, dict] = {
    "quick": {
        "description": "Headers and file exposure only — fast, no input fuzzing",
        "run_xss":        False,
        "run_sqli":       False,
        "run_blind_sqli": False,
        "run_stored_xss": False,
        "run_csrf":       True,
        "run_idor":       False,
        "run_headers":    True,
        "run_redirects":  False,
        "run_exposure":   True,
        "run_info_leak":  True,
    },
    "standard": {
        "description": "Full input testing excluding slow blind SQLi and IDOR",
        "run_xss":        True,
        "run_sqli":       True,
        "run_blind_sqli": False,
        "run_stored_xss": True,
        "run_csrf":       True,
        "run_idor":       False,
        "run_headers":    True,
        "run_redirects":  True,
        "run_exposure":   True,
        "run_info_leak":  True,
    },
    "full": {
        "description": "Everything — slowest but most thorough",
        "run_xss":        True,
        "run_sqli":       True,
        "run_blind_sqli": True,
        "run_stored_xss": True,
        "run_csrf":       True,
        "run_idor":       True,
        "run_headers":    True,
        "run_redirects":  True,
        "run_exposure":   True,
        "run_info_leak":  True,
    },
    "api": {
        "description": "API-focused: JSON endpoints, headers, no HTML form tests",
        "run_xss":        True,
        "run_sqli":       True,
        "run_blind_sqli": False,
        "run_stored_xss": False,
        "run_csrf":       False,
        "run_idor":       True,
        "run_headers":    True,
        "run_redirects":  True,
        "run_exposure":   True,
        "run_info_leak":  True,
    },
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
