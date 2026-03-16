"""
db/database.py — Async MongoDB client via Motor.
"""

import os
import logging
import certifi
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import ServerSelectionTimeoutError

log = logging.getLogger(__name__)

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


async def connect_db() -> None:
    global _client, _db
    url     = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    db_name = os.getenv("DB_NAME", "webscan")

    client_options: dict = {
        "serverSelectionTimeoutMS": 10000,
        "connectTimeoutMS": 20000,
        "socketTimeoutMS": 20000,
    }

    # Atlas (mongodb+srv) needs TLS with a trusted CA bundle.
    # Do NOT mix tlsAllowInvalidCertificates with tlsDisableOCSPEndpointCheck —
    # pymongo raises InvalidURI if both are set.
    if url.startswith("mongodb+srv://") or "mongodb.net" in url:
        client_options["tls"]       = True
        client_options["tlsCAFile"] = certifi.where()

    _client = AsyncIOMotorClient(url, **client_options)
    _db     = _client[db_name]

    try:
        await _client.admin.command("ping")
    except ServerSelectionTimeoutError as exc:
        log.error("MongoDB connection failed: %s", exc)
        raise RuntimeError(
            "Cannot reach MongoDB. Check your MONGODB_URL, Atlas IP allowlist "
            "(add 0.0.0.0/0 for Render), and that your password has no special "
            "characters that need URL-encoding."
        ) from exc

    await _db.users.create_index([("username", ASCENDING)], unique=True)
    await _db.users.create_index([("email",    ASCENDING)], unique=True)
    await _db.scans.create_index([("user_id",  ASCENDING)])
    await _db.scans.create_index([("created_at", DESCENDING)])
    log.info("MongoDB connected to %s", url.split("@")[-1])


async def close_db() -> None:
    global _client
    if _client:
        _client.close()


def get_db() -> AsyncIOMotorDatabase:
    if _db is None:
        raise RuntimeError("Database not initialised — call connect_db() first")
    return _db
