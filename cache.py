"""
cache.py
--------
Lightweight file-based cache for the last discovery results.
No credentials are ever cached — only VM inventory data.
"""

import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

CACHE_FILE = os.path.join(os.path.dirname(__file__), "cache", "last_inventory.json")


def _ensure_dir():
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)


def save(records: list[dict], host: str) -> None:
    """Persist inventory records to disk with a timestamp."""
    _ensure_dir()
    payload = {
        "host":      host,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "count":     len(records),
        "records":   records,
    }
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        logger.info("Cached %d VM records for %s", len(records), host)
    except OSError as exc:
        logger.warning("Could not write cache: %s", exc)


def load() -> dict | None:
    """
    Load cached results. Returns the full payload dict or None
    if no cache exists or the file is corrupt.
    """
    if not os.path.exists(CACHE_FILE):
        return None
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read cache: %s", exc)
        return None


def clear() -> None:
    """Remove the cache file."""
    try:
        os.remove(CACHE_FILE)
    except FileNotFoundError:
        pass
