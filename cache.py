"""
cache.py
--------
File-based cache for discovery results.
Stores one JSON file per host under cache/hosts/<host>.json.
Legacy single-file cache/last_inventory.json is kept for backward-compat.
No credentials are ever cached — only VM inventory data.
"""

import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

_BASE      = os.path.dirname(__file__)
CACHE_DIR  = os.path.join(_BASE, "cache")
CACHE_FILE = os.path.join(CACHE_DIR, "last_inventory.json")   # legacy
HOSTS_DIR  = os.path.join(CACHE_DIR, "hosts")


def _safe_name(host: str) -> str:
    return host.replace("/", "_").replace(":", "_").replace("\\", "_") + ".json"


def _ensure_dirs():
    os.makedirs(CACHE_DIR, exist_ok=True)
    os.makedirs(HOSTS_DIR, exist_ok=True)


def _write(path: str, payload: dict) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
    except OSError as exc:
        logger.warning("Could not write cache %s: %s", path, exc)


def save(records: list[dict], host: str) -> None:
    """Persist inventory records for host. Writes per-host file + legacy file."""
    _ensure_dirs()
    payload = {
        "host":      host,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "count":     len(records),
        "records":   records,
    }
    _write(os.path.join(HOSTS_DIR, _safe_name(host)), payload)
    _write(CACHE_FILE, payload)
    logger.info("Cached %d VM records for %s", len(records), host)


def load() -> dict | None:
    """Load the legacy single-file cache (last discovery, any host)."""
    if not os.path.exists(CACHE_FILE):
        return None
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read cache: %s", exc)
        return None


def load_host(host: str) -> dict | None:
    """Load cached results for a specific host."""
    path = os.path.join(HOSTS_DIR, _safe_name(host))
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not read host cache for %s: %s", host, exc)
        return None


def list_hosts() -> list[str]:
    """Return sorted list of all host names that have a cache file."""
    hosts = set()

    # Read per-host files
    if os.path.exists(HOSTS_DIR):
        for fname in os.listdir(HOSTS_DIR):
            if not fname.endswith(".json"):
                continue
            fpath = os.path.join(HOSTS_DIR, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if "host" in data:
                    hosts.add(data["host"])
            except (OSError, json.JSONDecodeError):
                pass

    # Migrate legacy single-file if no per-host files exist yet
    if not hosts and os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            h = data.get("host")
            if h:
                _ensure_dirs()
                _write(os.path.join(HOSTS_DIR, _safe_name(h)), data)
                hosts.add(h)
        except (OSError, json.JSONDecodeError):
            pass

    return sorted(hosts)


def load_all_hosts() -> list[dict]:
    """
    Merge VM records from every per-host cache file.
    Injects source_host and discovered_at into each record.
    Used as a fallback when the database is unavailable.
    """
    if not os.path.exists(HOSTS_DIR):
        return []
    all_records = []
    for fname in sorted(os.listdir(HOSTS_DIR)):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(HOSTS_DIR, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            h  = data.get("host", "")
            ts = data.get("timestamp", "")
            for rec in data.get("records", []):
                r = dict(rec)
                r.setdefault("source_host",   h)
                r.setdefault("discovered_at", ts)
                all_records.append(r)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not read host cache %s: %s", fname, exc)
    return all_records


def clear() -> None:
    """Remove the legacy cache file (per-host files are retained)."""
    try:
        os.remove(CACHE_FILE)
    except FileNotFoundError:
        pass
