"""
api/routes.py — All REST endpoints and WebSocket handler.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from bson import ObjectId
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse, PlainTextResponse

from api.auth import create_token, get_current_user, get_current_user_ws, hash_password, verify_password
from api.models import (
    DiffRequest, DiffResult, ScanConfig, ScanDetail, ScanListItem,
    ScanSummary, TokenResponse, UserLogin, UserRegister, UserResponse,
)
from db.database import get_db
from reporting.differ import ReportDiffer

log = logging.getLogger(__name__)
router = APIRouter()

# In-memory map of scan_id → asyncio.Queue for WebSocket streaming
_scan_queues: dict[str, asyncio.Queue] = {}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt_user(u: dict) -> UserResponse:
    return UserResponse(
        id=str(u["_id"]),
        username=u["username"],
        email=u["email"],
        created_at=u["created_at"],
    )


def _fmt_scan(s: dict) -> ScanListItem:
    raw_sum = s.get("summary", {})
    return ScanListItem(
        id=str(s["_id"]),
        target=s["target"],
        profile=s.get("profile", "standard"),
        status=s["status"],
        summary=ScanSummary(**raw_sum) if raw_sum else ScanSummary(),
        created_at=s["created_at"],
        completed_at=s.get("completed_at"),
    )


def _fmt_scan_detail(s: dict) -> ScanDetail:
    base = _fmt_scan(s)
    return ScanDetail(
        **base.model_dump(),
        config=ScanConfig(**s.get("config", {})),
        findings=s.get("findings", []),
        errors=s.get("errors", []),
    )


# ── Auth endpoints ─────────────────────────────────────────────────────────────

@router.post("/auth/register", response_model=TokenResponse, status_code=201)
async def register(body: UserRegister):
    db = get_db()
    if await db.users.find_one({"username": body.username}):
        raise HTTPException(400, "Username already taken")
    if await db.users.find_one({"email": body.email}):
        raise HTTPException(400, "Email already registered")

    user_id = str(uuid4())
    now = datetime.now(timezone.utc)
    doc = {
        "_id": user_id,
        "username": body.username,
        "email": body.email,
        "password_hash": hash_password(body.password),
        "created_at": now,
        "is_active": True,
    }
    await db.users.insert_one(doc)
    token = create_token(user_id, body.username)
    return TokenResponse(access_token=token, user=_fmt_user(doc))


@router.post("/auth/login", response_model=TokenResponse)
async def login(body: UserLogin):
    db = get_db()
    user = await db.users.find_one({"username": body.username.lower()})
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(401, "Invalid username or password")
    if not user.get("is_active", True):
        raise HTTPException(403, "Account disabled")
    token = create_token(str(user["_id"]), user["username"])
    return TokenResponse(access_token=token, user=_fmt_user(user))


@router.get("/users/me", response_model=UserResponse)
async def me(user=Depends(get_current_user)):
    return _fmt_user(user)


@router.put("/users/me/password", status_code=204)
async def change_password(
    body: dict,
    user=Depends(get_current_user),
):
    if not verify_password(body.get("current_password", ""), user["password_hash"]):
        raise HTTPException(400, "Current password is incorrect")
    new_pw = body.get("new_password", "")
    if len(new_pw) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    db = get_db()
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {"password_hash": hash_password(new_pw)}},
    )


# ── Scan endpoints ─────────────────────────────────────────────────────────────

@router.post("/scans", response_model=ScanListItem, status_code=201)
async def start_scan(
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
    return _fmt_scan(doc)


@router.get("/scans", response_model=list[ScanListItem])
async def list_scans(
    limit: int = Query(default=20, le=100),
    user=Depends(get_current_user),
):
    db = get_db()
    cursor = db.scans.find(
        {"user_id": str(user["_id"])},
        sort=[("created_at", -1)],
    ).limit(limit)
    return [_fmt_scan(s) async for s in cursor]


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str, user=Depends(get_current_user)):
    scan = await _get_scan_owned(scan_id, str(user["_id"]))
    return _fmt_scan_detail(scan)


@router.delete("/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, user=Depends(get_current_user)):
    db = get_db()
    res = await db.scans.delete_one(
        {"_id": scan_id, "user_id": str(user["_id"])}
    )
    if res.deleted_count == 0:
        raise HTTPException(404, "Scan not found")
    _scan_queues.pop(scan_id, None)


@router.get("/scans/{scan_id}/report/html", response_class=HTMLResponse)
async def report_html(scan_id: str, user=Depends(get_current_user)):
    scan = await _get_scan_owned(scan_id, str(user["_id"]))
    from reporting.reporter import Reporter
    from scanner.async_engine import ScanResult
    result = _scan_doc_to_result(scan)
    return Reporter(result).export_html_str()


@router.get("/scans/{scan_id}/report/markdown", response_class=PlainTextResponse)
async def report_markdown(scan_id: str, user=Depends(get_current_user)):
    scan = await _get_scan_owned(scan_id, str(user["_id"]))
    from reporting.reporter import Reporter
    result = _scan_doc_to_result(scan)
    return Reporter(result).export_markdown_str()


@router.get("/scans/{scan_id}/report/json")
async def report_json(scan_id: str, user=Depends(get_current_user)):
    scan = await _get_scan_owned(scan_id, str(user["_id"]))
    from reporting.reporter import Reporter
    result = _scan_doc_to_result(scan)
    return Reporter(result).export_json_dict()


# ── Report diff ───────────────────────────────────────────────────────────────

@router.post("/reports/diff", response_model=DiffResult)
async def diff_reports(body: DiffRequest, user=Depends(get_current_user)):
    uid = str(user["_id"])
    scan_a = await _get_scan_owned(body.scan_id_before, uid)
    scan_b = await _get_scan_owned(body.scan_id_after, uid)
    differ = ReportDiffer(scan_a.get("findings", []), scan_b.get("findings", []))
    return differ.diff()


# ── WebSocket ─────────────────────────────────────────────────────────────────

@router.websocket("/ws/{scan_id}")
async def scan_websocket(
    websocket: WebSocket,
    scan_id: str,
    token: str = Query(...),
):
    user = await get_current_user_ws(token)
    if not user:
        await websocket.close(code=4001)
        return

    db   = get_db()
    scan = await db.scans.find_one({"_id": scan_id, "user_id": str(user["_id"])})
    if not scan:
        await websocket.close(code=4004)
        return

    await websocket.accept()

    # If scan already complete, replay summary and close
    if scan["status"] in ("complete", "error"):
        await websocket.send_json({
            "type": "complete",
            "data": {"summary": scan.get("summary", {}), "status": scan["status"]},
        })
        await websocket.close()
        return

    # Otherwise, relay messages from the queue
    q = _scan_queues.get(scan_id)
    if not q:
        await websocket.close(code=4003)
        return

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


# ── Background scan task ──────────────────────────────────────────────────────

async def _run_scan_task(scan_id: str, config: ScanConfig, q: asyncio.Queue):
    """Runs in the background; pushes progress to q and saves results to DB."""
    from scanner.async_engine import AsyncScannerEngine
    db = get_db()

    await db.scans.update_one(
        {"_id": scan_id},
        {"$set": {"status": "running", "started_at": datetime.now(timezone.utc)}},
    )

    try:
        engine = AsyncScannerEngine(config)
        result = await engine.run(q)

        summary = {
            "total": len(result.findings),
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
            {"$set": {
                "status": "complete",
                "findings": result.findings,
                "errors": result.errors,
                "summary": summary,
                "completed_at": datetime.now(timezone.utc),
            }},
        )

        await q.put({"type": "complete", "data": {"summary": summary, "status": "complete"}})

    except Exception as exc:
        log.exception("Scan %s failed: %s", scan_id, exc)
        await db.scans.update_one(
            {"_id": scan_id},
            {"$set": {
                "status": "error",
                "errors": [str(exc)],
                "completed_at": datetime.now(timezone.utc),
            }},
        )
        await q.put({"type": "error", "data": {"message": str(exc)}})
    finally:
        # Leave queue in place briefly for any late WebSocket connects
        await asyncio.sleep(10)
        _scan_queues.pop(scan_id, None)


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_scan_owned(scan_id: str, user_id: str) -> dict:
    db   = get_db()
    scan = await db.scans.find_one({"_id": scan_id, "user_id": user_id})
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


def _scan_doc_to_result(scan: dict):
    """Converts a MongoDB scan document into a minimal ScanResult-like object."""
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
