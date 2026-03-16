"""
api/auth.py — JWT auth using direct bcrypt (no passlib), rate-limit helpers,
              admin dependency, token blacklist, and audit logging.
"""
import hashlib
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt

from db.database import get_db

log = logging.getLogger(__name__)

_bearer      = HTTPBearer(auto_error=False)
SECRET_KEY   = os.getenv("JWT_SECRET", "dev-secret-CHANGE-THIS")
ALGORITHM    = os.getenv("JWT_ALGORITHM", "HS256")
EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES    = 15


# ── Password hashing (bcrypt direct, no passlib) ──────────────────────────────
# bcrypt has a hard 72-byte limit. We SHA-256 the password first so any length
# works safely, then run the hex digest through bcrypt.

def _prep(plain: str) -> bytes:
    return hashlib.sha256(plain.encode("utf-8")).hexdigest().encode("utf-8")

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(_prep(plain), bcrypt.gensalt(rounds=12)).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(_prep(plain), hashed.encode("utf-8"))
    except Exception:
        return False


# ── JWT ───────────────────────────────────────────────────────────────────────

def create_token(user_id: str, username: str, is_admin: bool = False) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=EXPIRE_HOURS)
    return jwt.encode(
        {"sub": user_id, "username": username, "is_admin": is_admin, "exp": expire},
        SECRET_KEY, algorithm=ALGORITHM,
    )

def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_client_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return getattr(request.client, "host", "unknown")


# ── Brute-force protection ────────────────────────────────────────────────────

async def check_ip_locked(ip: str) -> None:
    db     = get_db()
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_MINUTES)
    count  = await db.login_attempts.count_documents(
        {"ip": ip, "success": False, "timestamp": {"$gte": cutoff}}
    )
    if count >= MAX_LOGIN_ATTEMPTS:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.",
        )

async def record_login_attempt(ip: str, username: str, success: bool) -> None:
    db = get_db()
    await db.login_attempts.insert_one({
        "ip": ip, "username": username,
        "success": success,
        "timestamp": datetime.now(timezone.utc),
    })
    await _write_audit(
        action="login_success" if success else "login_failed",
        username=username, ip=ip,
        detail="OK" if success else "Bad credentials",
        success=success,
    )


# ── Audit log ─────────────────────────────────────────────────────────────────

async def _write_audit(
    action: str,
    username: Optional[str] = None,
    user_id:  Optional[str] = None,
    ip:       Optional[str] = None,
    detail:   Optional[str] = None,
    success:  bool = True,
) -> None:
    try:
        db = get_db()
        await db.audit_log.insert_one({
            "timestamp": datetime.now(timezone.utc),
            "action": action,
            "user_id": user_id,
            "username": username,
            "ip": ip,
            "detail": detail,
            "success": success,
        })
    except Exception as exc:
        log.warning("Audit log write failed: %s", exc)

async def audit(
    action: str,
    user: dict,
    request: Request,
    detail: Optional[str] = None,
    success: bool = True,
) -> None:
    await _write_audit(
        action=action,
        user_id=str(user.get("_id", "")),
        username=user.get("username"),
        ip=get_client_ip(request),
        detail=detail,
        success=success,
    )


# ── Token blacklist ───────────────────────────────────────────────────────────

async def blacklist_token(token: str) -> None:
    payload = decode_token(token)
    if not payload:
        return
    db = get_db()
    await db.token_blacklist.replace_one(
        {"token": token},
        {"token": token, "expires_at": datetime.fromtimestamp(payload["exp"], tz=timezone.utc)},
        upsert=True,
    )

async def is_blacklisted(token: str) -> bool:
    db  = get_db()
    doc = await db.token_blacklist.find_one({"token": token})
    return doc is not None


# ── FastAPI dependencies ──────────────────────────────────────────────────────

async def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    if not creds:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token   = creds.credentials
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    if await is_blacklisted(token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token revoked — please log in again")
    db   = get_db()
    user = await db.users.find_one({"_id": payload["sub"]})
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if not user.get("is_active", True):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Account suspended")
    return user

async def get_current_admin(user: dict = Depends(get_current_user)) -> dict:
    if not user.get("is_admin", False):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user

async def get_current_user_ws(token: str) -> Optional[dict]:
    payload = decode_token(token)
    if not payload:
        return None
    if await is_blacklisted(token):
        return None
    db   = get_db()
    user = await db.users.find_one({"_id": payload["sub"]})
    if not user or not user.get("is_active", True):
        return None
    return user
