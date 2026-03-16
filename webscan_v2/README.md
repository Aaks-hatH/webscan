# WebScan v2 — Full-Stack Security Scanner

> **Authorized testing environments only.**

A complete web vulnerability scanner with a FastAPI backend, async scan engine,
MongoDB persistence, JWT auth, WebSocket live progress, and a dark-mode SPA frontend.
One-command deploy to Render.

---

## Stack

| Layer | Technology |
|-------|-----------|
| API server | FastAPI + uvicorn |
| HTTP client | httpx (async, HTTP/2) |
| HTML parsing | BeautifulSoup4 + lxml |
| Auth | JWT (python-jose) + bcrypt (passlib) |
| Database | MongoDB via Motor (async) |
| Live progress | WebSockets |
| Frontend | Vanilla JS SPA (zero dependencies) |
| Deploy | Render (render.yaml included) |

---

## Quick Start (local)

```bash
# 1. Clone / unzip
cd webscan_v2

# 2. Create virtualenv
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install deps
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env — set MONGODB_URL and JWT_SECRET

# 5. Start MongoDB (Docker)
docker run -d -p 27017:27017 --name mongo mongo:7

# 6. Run server
uvicorn server:app --reload --port 8000

# 7. Open browser
open http://localhost:8000
```

The API docs are at `http://localhost:8000/api/docs`.

---

## Deploy to Render

1. Push this folder to a GitHub repository
2. Create a new **Web Service** on [render.com](https://render.com)
3. Set **Build Command:** `pip install -r requirements.txt`
4. Set **Start Command:** `uvicorn server:app --host 0.0.0.0 --port $PORT`
5. Add environment variables:
   - `MONGODB_URL` — your MongoDB Atlas connection string
   - `JWT_SECRET` — long random string (Render can auto-generate)
   - `ENVIRONMENT` — `production`

Free MongoDB Atlas cluster: https://www.mongodb.com/atlas/database

---

## Project Structure

```
webscan_v2/
├── server.py                  # FastAPI app entry point
├── config.py                  # All probes, patterns, profiles
├── requirements.txt
├── render.yaml                # Render deploy config
├── .env.example
│
├── api/
│   ├── auth.py                # JWT creation, bcrypt, FastAPI dependency
│   ├── models.py              # Pydantic v2 request/response schemas
│   └── routes.py              # All REST + WebSocket endpoints
│
├── db/
│   └── database.py            # Motor async MongoDB client
│
├── crawler/
│   └── async_crawler.py       # Async BFS crawler (httpx + semaphore)
│
├── discovery/
│   └── input_discovery.py     # Input surface aggregation
│
├── detection/
│   ├── finding.py             # Shared Finding dataclass
│   ├── xss_detector.py        # Reflected XSS
│   ├── sqli_detector.py       # Error-based SQLi
│   ├── blind_sqli.py          # Time-based blind SQLi ← NEW
│   ├── stored_xss.py          # Stored / persistent XSS ← NEW
│   ├── csrf_detector.py       # CSRF token absence ← NEW
│   ├── idor_detector.py       # Insecure Direct Object Reference ← NEW
│   ├── header_checker.py      # Security headers + cookie flags
│   ├── redirect_detector.py   # Open redirects
│   └── exposure_detector.py   # File exposure + info leak regex
│
├── scanner/
│   └── async_engine.py        # Full async orchestrator with progress queue
│
├── reporting/
│   ├── reporter.py            # JSON / Markdown / HTML report generation
│   └── differ.py              # Report diff (new/resolved/regressed) ← NEW
│
└── static/
    └── index.html             # Complete SPA frontend (dark mode)
```

---

## Scan Profiles

| Profile | Description | Checks |
|---------|-------------|--------|
| `quick` | Fast, no fuzzing | Headers, file exposure, info leak, CSRF |
| `standard` | Recommended | + XSS, SQLi, stored XSS, redirects |
| `full` | Thorough, slower | + Blind SQLi (timing), IDOR |
| `api` | API targets | + JSON endpoints, IDOR; no HTML forms |

---

## API Endpoints

```
POST   /api/auth/register          Register new account
POST   /api/auth/login             Login → JWT token
GET    /api/users/me               Current user
PUT    /api/users/me/password      Change password

POST   /api/scans                  Start scan (returns scan_id)
GET    /api/scans                  List all scans
GET    /api/scans/{id}             Scan detail + findings
DELETE /api/scans/{id}             Delete scan
GET    /api/scans/{id}/report/html    HTML report
GET    /api/scans/{id}/report/markdown Markdown report
GET    /api/scans/{id}/report/json    JSON report

POST   /api/reports/diff           Diff two scan reports

WS     /api/ws/{scan_id}?token=…  Live scan progress
```

Full interactive docs: `/api/docs`

---

## Recommended Test Targets

```bash
# OWASP Juice Shop (most comprehensive)
docker run -d -p 3000:3000 bkimminich/juice-shop

# DVWA
docker run -d -p 8080:80 vulnerables/web-dvwa

# WebGoat
docker run -d -p 8888:8080 webgoat/webgoat
```

---

## Legal Notice

For use only on systems you own or have explicit written permission to test.
Unauthorized scanning is illegal in most jurisdictions.
