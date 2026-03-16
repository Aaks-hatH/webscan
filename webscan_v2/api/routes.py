"""
api/routes.py — All REST + WebSocket endpoints.
  - Rate limiting via slowapi
  - Login brute-force protection
  - Token blacklist / logout
  - Full admin panel endpoints
  - Audit logging on all sensitive actions
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from api.auth import (
    audit, blacklist_token, check_ip_locked, create_token,
    get_client_ip, get_current_admin, get_current_user, get_current_user_ws,
    hash_password, record_login_attempt, verify_password,
)
from api.models import (
    AdminUserUpdate, AuditEntry, DiffRequest, DiffResult,
    ScanConfig, ScanDetail, ScanListItem, ScanSummary,
    SystemStats, TokenResponse, UserLogin, UserRegister, UserResponse,
)
from db.database import get_db
from reporting.differ import ReportDiffer

log     = logging.getLogger(__name__)
router  = APIRouter()
limiter = Limiter(key_func=get_remote_address)

_scan_queues: dict[str, asyncio.Queue] = {}


# ── Formatters ────────────────────────────────────────────────────────────────

def _fmt_user(u: dict) -> UserResponse:
    return UserResponse(
        id=str(u["_id"]),
        username=u["username"],
        email=u["email"],
        created_at=u["created_at"],
        is_admin=u.get("is_admin", False),
        is_active=u.get("is_active", True),
        last_login=u.get("last_login"),
    )

def _fmt_scan(s: dict, username: str = "") -> ScanListItem:
    raw = s.get("summary", {})
    return ScanListItem(
        id=str(s["_id"]),
        target=s["target"],
        profile=s.get("profile", "standard"),
        status=s["status"],
        summary=ScanSummary(**raw) if raw else ScanSummary(),
        created_at=s["created_at"],
        completed_at=s.get("completed_at"),
        user_id=s.get("user_id"),
        username=username or s.get("username", ""),
    )

def _fmt_scan_detail(s: dict) -> ScanDetail:
    base = _fmt_scan(s)
    return ScanDetail(
        **base.model_dump(),
        config=ScanConfig(**s.get("config", {"target": s.get("target", ""), "profile": "standard"})),
        findings=s.get("findings", []),
        errors=s.get("errors", []),
    )


# ── Auth ──────────────────────────────────────────────────────────────────────

@router.post("/auth/register", response_model=TokenResponse, status_code=201)
@limiter.limit("10/hour")
async def register(request: Request, body: UserRegister):
    db = get_db()
    if await db.users.find_one({"username": body.username}):
        raise HTTPException(400, "Username already taken")
    if await db.users.find_one({"email": body.email}):
        raise HTTPException(400, "Email already registered")

    # First-ever user becomes admin automatically
    is_first = await db.users.count_documents({}) == 0

    uid = str(uuid4())
    now = datetime.now(timezone.utc)
    doc = {
        "_id": uid,
        "username": body.username,
        "email": body.email,
        "password_hash": hash_password(body.password),
        "created_at": now,
        "is_active": True,
        "is_admin": is_first,
        "last_login": now,
    }
    await db.users.insert_one(doc)
    from api.auth import _write_audit
    await _write_audit("register", username=body.username,
                       user_id=uid, ip=get_client_ip(request))
    token = create_token(uid, body.username, is_admin=is_first)
    return TokenResponse(access_token=token, user=_fmt_user(doc))


@router.post("/auth/login", response_model=TokenResponse)
@limiter.limit("20/minute")
async def login(request: Request, body: UserLogin):
    ip = get_client_ip(request)
    await check_ip_locked(ip)

    db   = get_db()
    user = await db.users.find_one({"username": body.username.lower()})
    if not user or not verify_password(body.password, user["password_hash"]):
        await record_login_attempt(ip, body.username, success=False)
        raise HTTPException(401, "Invalid username or password")
    if not user.get("is_active", True):
        raise HTTPException(403, "Account suspended")

    await record_login_attempt(ip, body.username, success=True)
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"last_login": datetime.now(timezone.utc)}}
    )
    token = create_token(str(user["_id"]), user["username"], is_admin=user.get("is_admin", False))
    return TokenResponse(access_token=token, user=_fmt_user(user))


@router.post("/auth/logout", status_code=204)
async def logout(request: Request, user=Depends(get_current_user)):
    from fastapi.security import HTTPBearer
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        await blacklist_token(auth_header[7:])
    await audit("logout", user, request)


@router.get("/users/me", response_model=UserResponse)
async def me(user=Depends(get_current_user)):
    return _fmt_user(user)


@router.put("/users/me/password", status_code=204)
async def change_password(body: dict, request: Request, user=Depends(get_current_user)):
    if not verify_password(body.get("current_password", ""), user["password_hash"]):
        raise HTTPException(400, "Current password is incorrect")
    new_pw = body.get("new_password", "")
    if len(new_pw) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    db = get_db()
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"password_hash": hash_password(new_pw)}}
    )
    await audit("password_change", user, request)


# ── Scans ─────────────────────────────────────────────────────────────────────

@router.post("/scans", response_model=ScanListItem, status_code=201)
@limiter.limit("30/hour")
async def start_scan(
    request: Request,
    config: ScanConfig,
    background_tasks: BackgroundTasks,
    user=Depends(get_current_user),
):
    db      = get_db()
    scan_id = str(uuid4())
    now     = datetime.now(timezone.utc)
    doc = {
        "_id": scan_id,
        "user_id": str(user["_id"]),
        "username": user["username"],
        "target": config.target,
        "profile": config.profile,
        "config": config.model_dump(),
        "status": "pending",
        "summary": {},
        "findings": [],
        "errors": [],
        "created_at": now,
        "completed_at": None,
    }
    await db.scans.insert_one(doc)
    q: asyncio.Queue = asyncio.Queue()
    _scan_queues[scan_id] = q
    background_tasks.add_task(_run_scan_task, scan_id, config, q)
    await audit("scan_start", user, request, detail=config.target)
    return _fmt_scan(doc, username=user["username"])


@router.get("/scans", response_model=list[ScanListItem])
async def list_scans(limit: int = Query(default=20, le=100), user=Depends(get_current_user)):
    db = get_db()
    cursor = db.scans.find({"user_id": str(user["_id"])}, sort=[("created_at", -1)]).limit(limit)
    return [_fmt_scan(s) async for s in cursor]


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str, user=Depends(get_current_user)):
    return _fmt_scan_detail(await _owned(scan_id, str(user["_id"])))


@router.delete("/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, request: Request, user=Depends(get_current_user)):
    db  = get_db()
    res = await db.scans.delete_one({"_id": scan_id, "user_id": str(user["_id"])})
    if res.deleted_count == 0:
        raise HTTPException(404, "Scan not found")
    _scan_queues.pop(scan_id, None)
    await audit("scan_delete", user, request, detail=scan_id)


async def _resolve_report_user(
    scan_id: str,
    user=Depends(get_current_user),
    token: Optional[str] = Query(default=None),
) -> tuple[dict, str]:
    """
    Resolve auth for report endpoints.
    Browser tabs can't send Authorization headers, so we also accept
    ?token=<jwt> as a query parameter — identical to how WebSockets work.
    """
    if user:
        return user, scan_id
    # Fallback: validate token from query string
    if token:
        from api.auth import decode_token, is_blacklisted
        payload = decode_token(token)
        if payload and not await is_blacklisted(token):
            db   = get_db()
            u    = await db.users.find_one({"_id": payload["sub"]})
            if u and u.get("is_active", True):
                return u, scan_id
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


async def _get_report_scan(scan_id: str, token: Optional[str] = Query(default=None)) -> dict:
    """Shared dependency: authenticate via header OR ?token= query param."""
    from api.auth import decode_token, is_blacklisted
    from fastapi.security import HTTPBearer
    db = get_db()

    # Try to get user from token query param first (browser tab use)
    if token:
        payload = decode_token(token)
        if payload and not await is_blacklisted(token):
            u = await db.users.find_one({"_id": payload["sub"]})
            if u and u.get("is_active", True):
                scan = await db.scans.find_one({"_id": scan_id, "user_id": str(u["_id"])})
                if not scan:
                    # Admins can view any scan
                    if u.get("is_admin"):
                        scan = await db.scans.find_one({"_id": scan_id})
                if scan:
                    return scan
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


@router.get("/scans/{scan_id}/report/html", response_class=HTMLResponse)
async def report_html(
    scan_id: str,
    token: Optional[str] = Query(default=None),
    user=Depends(get_current_user),
):
    from reporting.reporter import Reporter
    # Bearer token auth (API calls)
    try:
        scan = await _owned(scan_id, str(user["_id"]))
    except Exception:
        # Fallback: query param token (browser tab)
        scan = await _get_report_scan(scan_id, token)
    return Reporter(_scan_to_result(scan)).export_html_str()


@router.get("/scans/{scan_id}/report/markdown", response_class=PlainTextResponse)
async def report_markdown(
    scan_id: str,
    token: Optional[str] = Query(default=None),
    user=Depends(get_current_user),
):
    from reporting.reporter import Reporter
    try:
        scan = await _owned(scan_id, str(user["_id"]))
    except Exception:
        scan = await _get_report_scan(scan_id, token)
    return Reporter(_scan_to_result(scan)).export_markdown_str()


@router.get("/scans/{scan_id}/report/json")
async def report_json(
    scan_id: str,
    token: Optional[str] = Query(default=None),
    user=Depends(get_current_user),
):
    from reporting.reporter import Reporter
    try:
        scan = await _owned(scan_id, str(user["_id"]))
    except Exception:
        scan = await _get_report_scan(scan_id, token)
    return Reporter(_scan_to_result(scan)).export_json_dict()


@router.post("/reports/diff", response_model=DiffResult)
async def diff_reports(body: DiffRequest, user=Depends(get_current_user)):
    uid = str(user["_id"])
    a   = await _owned(body.scan_id_before, uid)
    b   = await _owned(body.scan_id_after,  uid)
    return ReportDiffer(a.get("findings", []), b.get("findings", [])).diff()


# ── WebSocket ─────────────────────────────────────────────────────────────────

@router.websocket("/ws/{scan_id}")
async def scan_ws(websocket: WebSocket, scan_id: str, token: str = Query(...)):
    user = await get_current_user_ws(token)
    if not user:
        await websocket.close(code=4001); return
    db   = get_db()
    scan = await db.scans.find_one({"_id": scan_id, "user_id": str(user["_id"])})
    if not scan:
        await websocket.close(code=4004); return
    await websocket.accept()
    if scan["status"] in ("complete", "error"):
        await websocket.send_json({"type": "complete", "data": {"summary": scan.get("summary", {}), "status": scan["status"]}})
        await websocket.close(); return
    q = _scan_queues.get(scan_id)
    if not q:
        await websocket.close(code=4003); return
    try:
        while True:
            msg = await asyncio.wait_for(q.get(), timeout=120.0)
            await websocket.send_json(msg)
            if msg.get("type") in ("complete", "error"):
                break
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        await websocket.close()


# ── Admin ─────────────────────────────────────────────────────────────────────

@router.get("/admin/stats", response_model=SystemStats)
async def admin_stats(admin=Depends(get_current_admin)):
    db  = get_db()
    now = datetime.now(timezone.utc)
    cutoff_24h = now - timedelta(hours=24)

    total_users    = await db.users.count_documents({})
    active_users   = await db.users.count_documents({"is_active": True})
    admin_users    = await db.users.count_documents({"is_admin": True})
    total_scans    = await db.scans.count_documents({})
    running_scans  = await db.scans.count_documents({"status": "running"})
    complete_scans = await db.scans.count_documents({"status": "complete"})
    failed_logins  = await db.login_attempts.count_documents(
        {"success": False, "timestamp": {"$gte": cutoff_24h}}
    )

    # Count findings across all completed scans
    pipeline = [
        {"$match": {"status": "complete"}},
        {"$project": {"total": "$summary.total", "critical": "$summary.critical"}},
        {"$group": {"_id": None,
                    "tf": {"$sum": "$total"},
                    "cf": {"$sum": "$critical"}}},
    ]
    agg = await db.scans.aggregate(pipeline).to_list(1)
    total_findings    = agg[0]["tf"] if agg else 0
    critical_findings = agg[0]["cf"] if agg else 0

    return SystemStats(
        total_users=total_users,
        active_users=active_users,
        admin_users=admin_users,
        total_scans=total_scans,
        running_scans=running_scans,
        complete_scans=complete_scans,
        total_findings=total_findings,
        critical_findings=critical_findings,
        failed_logins_24h=failed_logins,
    )


@router.get("/admin/users")
async def admin_list_users(
    limit:  int = Query(default=50, le=200),
    skip:   int = Query(default=0, ge=0),
    search: str = Query(default=""),
    admin=Depends(get_current_admin),
):
    db     = get_db()
    filt   = {}
    if search:
        import re
        filt["$or"] = [
            {"username": {"$regex": re.escape(search), "$options": "i"}},
            {"email":    {"$regex": re.escape(search), "$options": "i"}},
        ]
    cursor = db.users.find(filt, sort=[("created_at", -1)]).skip(skip).limit(limit)
    users  = []
    async for u in cursor:
        scan_count = await db.scans.count_documents({"user_id": str(u["_id"])})
        users.append({
            "id":         str(u["_id"]),
            "username":   u["username"],
            "email":      u["email"],
            "is_admin":   u.get("is_admin", False),
            "is_active":  u.get("is_active", True),
            "created_at": u["created_at"].isoformat(),
            "last_login": u["last_login"].isoformat() if u.get("last_login") else None,
            "scan_count": scan_count,
        })
    total = await db.users.count_documents(filt)
    return {"users": users, "total": total}


@router.patch("/admin/users/{user_id}")
async def admin_update_user(
    user_id: str,
    body: AdminUserUpdate,
    request: Request,
    admin=Depends(get_current_admin),
):
    if user_id == str(admin["_id"]) and body.is_admin is False:
        raise HTTPException(400, "Cannot remove your own admin rights")
    db      = get_db()
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(400, "No fields to update")
    res = await db.users.update_one({"_id": user_id}, {"$set": updates})
    if res.matched_count == 0:
        raise HTTPException(404, "User not found")
    await audit("admin_update_user", admin, request, detail=f"user={user_id} {updates}")
    return {"ok": True}


@router.delete("/admin/users/{user_id}", status_code=204)
async def admin_delete_user(
    user_id: str,
    request: Request,
    admin=Depends(get_current_admin),
):
    if user_id == str(admin["_id"]):
        raise HTTPException(400, "Cannot delete your own account via admin panel")
    db = get_db()
    await db.users.delete_one({"_id": user_id})
    await db.scans.delete_many({"user_id": user_id})
    await audit("admin_delete_user", admin, request, detail=f"deleted user={user_id}")


@router.get("/admin/scans")
async def admin_list_scans(
    limit: int = Query(default=50, le=200),
    skip:  int = Query(default=0, ge=0),
    admin=Depends(get_current_admin),
):
    db     = get_db()
    cursor = db.scans.find({}, sort=[("created_at", -1)]).skip(skip).limit(limit)
    scans  = [_fmt_scan(s).model_dump() async for s in cursor]
    total  = await db.scans.count_documents({})
    return {"scans": scans, "total": total}


@router.delete("/admin/scans/{scan_id}", status_code=204)
async def admin_delete_scan(scan_id: str, request: Request, admin=Depends(get_current_admin)):
    db = get_db()
    await db.scans.delete_one({"_id": scan_id})
    _scan_queues.pop(scan_id, None)
    await audit("admin_delete_scan", admin, request, detail=scan_id)


@router.get("/admin/audit")
async def admin_audit_log(
    limit:  int = Query(default=100, le=500),
    skip:   int = Query(default=0, ge=0),
    action: str = Query(default=""),
    admin=Depends(get_current_admin),
):
    db   = get_db()
    filt = {}
    if action:
        filt["action"] = action
    cursor  = db.audit_log.find(filt, sort=[("timestamp", -1)]).skip(skip).limit(limit)
    entries = []
    async for e in cursor:
        entries.append({
            "id":        str(e["_id"]),
            "timestamp": e["timestamp"].isoformat(),
            "action":    e.get("action"),
            "username":  e.get("username"),
            "ip":        e.get("ip"),
            "detail":    e.get("detail"),
            "success":   e.get("success", True),
        })
    total = await db.audit_log.count_documents(filt)
    return {"entries": entries, "total": total}


@router.get("/admin/login-attempts")
async def admin_login_attempts(
    limit: int = Query(default=100, le=500),
    admin=Depends(get_current_admin),
):
    db     = get_db()
    cursor = db.login_attempts.find({}, sort=[("timestamp", -1)]).limit(limit)
    return [
        {
            "ip":        a.get("ip"),
            "username":  a.get("username"),
            "success":   a.get("success"),
            "timestamp": a["timestamp"].isoformat(),
        }
        async for a in cursor
    ]


# ── Background scan task ──────────────────────────────────────────────────────

async def _run_scan_task(scan_id: str, config: ScanConfig, q: asyncio.Queue):
    from scanner.async_engine import AsyncScannerEngine
    db = get_db()
    await db.scans.update_one(
        {"_id": scan_id},
        {"$set": {"status": "running", "started_at": datetime.now(timezone.utc)}}
    )
    try:
        engine = AsyncScannerEngine(config)
        result = await engine.run(q)
        summary = {
            "total":   len(result.findings),
            "critical": sum(1 for f in result.findings if f["severity"] == "CRITICAL"),
            "high":     sum(1 for f in result.findings if f["severity"] == "HIGH"),
            "medium":   sum(1 for f in result.findings if f["severity"] == "MEDIUM"),
            "low":      sum(1 for f in result.findings if f["severity"] == "LOW"),
            "info":     sum(1 for f in result.findings if f["severity"] == "INFO"),
            "pages_crawled": result.pages_crawled,
            "duration_s":    result.duration_s,
            "input_vectors": result.input_vectors,
        }
        await db.scans.update_one(
            {"_id": scan_id},
            {"$set": {"status": "complete", "findings": result.findings,
                      "errors": result.errors, "summary": summary,
                      "completed_at": datetime.now(timezone.utc)}}
        )
        await q.put({"type": "complete", "data": {"summary": summary, "status": "complete"}})
    except Exception as exc:
        log.exception("Scan %s failed: %s", scan_id, exc)
        await db.scans.update_one(
            {"_id": scan_id},
            {"$set": {"status": "error", "errors": [str(exc)],
                      "completed_at": datetime.now(timezone.utc)}}
        )
        await q.put({"type": "error", "data": {"message": str(exc)}})
    finally:
        await asyncio.sleep(10)
        _scan_queues.pop(scan_id, None)


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _owned(scan_id: str, user_id: str) -> dict:
    db   = get_db()
    scan = await db.scans.find_one({"_id": scan_id, "user_id": user_id})
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


def _scan_to_result(scan: dict):
    from scanner.async_engine import ScanResult
    from detection.finding import Finding
    findings = [
        Finding(**{k: v for k, v in f.items() if k in Finding.__dataclass_fields__})
        for f in scan.get("findings", [])
    ]
    return ScanResult(
        target=scan["target"],
        duration_s=scan.get("summary", {}).get("duration_s", 0),
        pages_crawled=scan.get("summary", {}).get("pages_crawled", 0),
        input_vectors=scan.get("summary", {}).get("input_vectors", 0),
        findings=findings,
        errors=scan.get("errors", []),
    )
