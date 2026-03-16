"""
api/models.py — Pydantic v2 models for all API request and response schemas.
"""

from __future__ import annotations
from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, EmailStr, Field, field_validator


# ── Auth ──────────────────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("Username may only contain letters, numbers, _ and -")
        return v.lower()


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    created_at: datetime


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# ── Scan config ───────────────────────────────────────────────────────────────

class ScanConfig(BaseModel):
    target: str = Field(description="Root URL to scan")
    profile: str = Field(default="standard", description="quick | standard | full")
    max_depth: int = Field(default=3, ge=1, le=10)
    max_pages: int = Field(default=100, ge=1, le=500)
    delay: float = Field(default=0.3, ge=0.0, le=5.0)
    # Feature toggles (override profile defaults)
    run_xss: Optional[bool] = None
    run_sqli: Optional[bool] = None
    run_blind_sqli: Optional[bool] = None
    run_stored_xss: Optional[bool] = None
    run_csrf: Optional[bool] = None
    run_idor: Optional[bool] = None
    run_headers: Optional[bool] = None
    run_redirects: Optional[bool] = None
    run_exposure: Optional[bool] = None
    run_info_leak: Optional[bool] = None

    @field_validator("target")
    @classmethod
    def target_must_be_http(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("Target must start with http:// or https://")
        return v.rstrip("/")


# ── Scan status ───────────────────────────────────────────────────────────────

class ScanSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    pages_crawled: int = 0
    duration_s: float = 0.0
    input_vectors: int = 0


class ScanListItem(BaseModel):
    id: str
    target: str
    profile: str
    status: str        # pending | running | complete | error
    summary: ScanSummary
    created_at: datetime
    completed_at: Optional[datetime] = None


class ScanDetail(ScanListItem):
    config: ScanConfig
    findings: list[dict[str, Any]] = []
    errors: list[str] = []


# ── Report diff ───────────────────────────────────────────────────────────────

class DiffRequest(BaseModel):
    scan_id_before: str
    scan_id_after: str


class DiffResult(BaseModel):
    new_findings: list[dict[str, Any]]
    resolved_findings: list[dict[str, Any]]
    unchanged_count: int
    regression_count: int   # severity increased
    improvement_count: int  # severity decreased


# ── WebSocket messages ────────────────────────────────────────────────────────

class WSMessage(BaseModel):
    type: str    # phase | progress | finding | complete | error
    data: dict[str, Any] = {}
