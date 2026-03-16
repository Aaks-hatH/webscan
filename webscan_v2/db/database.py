"""db/database.py"""
import os
import logging
import certifi
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import ServerSelectionTimeoutError

log = logging.getLogger(__name__)
_client: AsyncIOMotorClient | None = None
_db:     AsyncIOMotorDatabase | None = None


async def connect_db() -> None:
    global _client, _db
    url     = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    db_name = os.getenv("DB_NAME", "webscan")

    opts: dict = {"serverSelectionTimeoutMS": 10000,
                  "connectTimeoutMS": 20000,
                  "socketTimeoutMS": 20000}

    if url.startswith("mongodb+srv://") or "mongodb.net" in url:
        opts["tls"]       = True
        opts["tlsCAFile"] = certifi.where()

    _client = AsyncIOMotorClient(url, **opts)
    _db     = _client[db_name]

    try:
        await _client.admin.command("ping")
    except ServerSelectionTimeoutError as exc:
        raise RuntimeError(
            "Cannot reach MongoDB. Check MONGODB_URL and Atlas IP allowlist "
            "(add 0.0.0.0/0 for Render)."
        ) from exc

    # User indexes
    await _db.users.create_index([("username", ASCENDING)], unique=True)
    await _db.users.create_index([("email",    ASCENDING)], unique=True)
    # Scan indexes
    await _db.scans.create_index([("user_id",    ASCENDING)])
    await _db.scans.create_index([("created_at", DESCENDING)])
    # Security indexes
    await _db.audit_log.create_index([("timestamp", DESCENDING)])
    await _db.audit_log.create_index([("user_id",   ASCENDING)])
    await _db.audit_log.create_index([("ip",        ASCENDING)])
    await _db.login_attempts.create_index([("ip",        ASCENDING)])
    await _db.login_attempts.create_index(
        [("timestamp", ASCENDING)], expireAfterSeconds=900)   # 15-min TTL
    await _db.token_blacklist.create_index(
        [("expires_at", ASCENDING)], expireAfterSeconds=0)    # auto-expire
    await _db.token_blacklist.create_index([("token", ASCENDING)], unique=True)

    log.info("MongoDB connected — %s", url.split("@")[-1])


async def close_db() -> None:
    global _client
    if _client:
        _client.close()


def get_db() -> AsyncIOMotorDatabase:
    if _db is None:
        raise RuntimeError("DB not initialised")
    return _db
