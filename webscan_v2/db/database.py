"""
db/database.py — Async MongoDB client via Motor.

Set MONGODB_URL in your environment (.env for local, Render env vars for prod).
Free MongoDB Atlas cluster: https://www.mongodb.com/atlas/database
"""

import os
import logging
import certifi
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING

log = logging.getLogger(__name__)

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


async def connect_db() -> None:
    global _client, _db
    url = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    db_name = os.getenv("DB_NAME", "webscan")

    client_options = {
        "serverSelectionTimeoutMS": 5000,
        "connectTimeoutMS": 20000,
        "socketTimeoutMS": 20000,
    }

    # Atlas deployments can fail TLS handshakes in minimal containers when the
    # system CA bundle is unavailable. Explicitly provide certifi's CA store.
    if url.startswith("mongodb+srv://") or "mongodb.net" in url:
        client_options["tls"] = True
        client_options["tlsAllowInvalidCertificates"] = False
        client_options["tlsCAFile"] = certifi.where()
        client_options["tlsAllowInvalidHostnames"] = False

    _client = AsyncIOMotorClient(url, **client_options)
    _db = _client[db_name]
    # Validate connection
    await _client.admin.command("ping")
    # Indexes
    await _db.users.create_index([("username", ASCENDING)], unique=True)
    await _db.users.create_index([("email", ASCENDING)], unique=True)
    await _db.scans.create_index([("user_id", ASCENDING)])
    await _db.scans.create_index([("created_at", DESCENDING)])
    log.info("MongoDB connected: %s / %s", url.split("@")[-1], db_name)


async def close_db() -> None:
    global _client
    if _client:
        _client.close()
        log.info("MongoDB connection closed")


def get_db() -> AsyncIOMotorDatabase:
    if _db is None:
        raise RuntimeError("Database not initialised — call connect_db() first")
    return _db
