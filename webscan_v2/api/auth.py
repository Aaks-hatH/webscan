"""
api/auth.py — JWT creation/validation and FastAPI auth dependency.
"""

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext

from db.database import get_db

log = logging.getLogger(__name__)

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
_bearer = HTTPBearer(auto_error=False)

SECRET_KEY   = os.getenv("JWT_SECRET", "dev-secret-change-in-production")
ALGORITHM    = os.getenv("JWT_ALGORITHM", "HS256")
EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))


# ── Password utilities ────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return _pwd.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd.verify(plain, hashed)


# ── JWT utilities ─────────────────────────────────────────────────────────────

def create_token(user_id: str, username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=EXPIRE_HOURS)
    return jwt.encode(
        {"sub": user_id, "username": username, "exp": expire},
        SECRET_KEY, algorithm=ALGORITHM,
    )


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


# ── FastAPI dependency ────────────────────────────────────────────────────────

async def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """Dependency — returns the current authenticated user document."""
    if not creds:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    payload = decode_token(creds.credentials)
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    db   = get_db()
    user = await db.users.find_one({"_id": payload["sub"]})
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if not user.get("is_active", True):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Account disabled")

    return user


async def get_current_user_ws(token: str) -> Optional[dict]:
    """WebSocket variant — returns None on failure instead of raising."""
    payload = decode_token(token)
    if not payload:
        return None
    db = get_db()
    return await db.users.find_one({"_id": payload["sub"]})
