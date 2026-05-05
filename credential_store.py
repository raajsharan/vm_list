"""
credential_store.py
-------------------
File-based encrypted storage for vCenter/ESXi credentials and schedule config.
Uses Fernet symmetric encryption. A key is auto-generated on first run and
persisted in cache/.cred_key (or taken from ENCRYPTION_KEY env var).
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_CACHE_DIR  = os.path.join(os.path.dirname(__file__), "cache")
_STORE_FILE = os.path.join(_CACHE_DIR, "credentials.json")
_KEY_FILE   = os.path.join(_CACHE_DIR, ".cred_key")


def _cipher() -> Fernet:
    raw = os.environ.get("ENCRYPTION_KEY")
    if raw:
        return Fernet(raw.encode() if isinstance(raw, str) else raw)
    os.makedirs(_CACHE_DIR, exist_ok=True)
    if os.path.exists(_KEY_FILE):
        with open(_KEY_FILE, "rb") as fh:
            return Fernet(fh.read().strip())
    key = Fernet.generate_key()
    with open(_KEY_FILE, "wb") as fh:
        fh.write(key)
    logger.info("Generated credential encryption key at %s", _KEY_FILE)
    return Fernet(key)


def _load_raw() -> dict:
    if not os.path.exists(_STORE_FILE):
        return {}
    try:
        with open(_STORE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Cannot read credential store: %s", exc)
        return {}


def _save_raw(data: dict) -> None:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    try:
        with open(_STORE_FILE, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
    except OSError as exc:
        logger.warning("Cannot write credential store: %s", exc)


def save(host: str, username: str, password: str,
         port: int = 443, verify_ssl: bool = False,
         interval_minutes: int = 60,
         enabled: bool | None = None) -> None:
    c    = _cipher()
    data = _load_raw()
    existing = data.get(host, {})
    # If caller passes explicit enabled value use it; else preserve existing (True for new hosts)
    new_enabled = enabled if enabled is not None else existing.get("enabled", True)
    data[host] = {
        "host":             host,
        "username":         username,
        "password_enc":     c.encrypt(password.encode()).decode(),
        "port":             port,
        "verify_ssl":       verify_ssl,
        "interval_minutes": interval_minutes,
        "enabled":          new_enabled,
        "last_run":         existing.get("last_run"),
        "last_status":      existing.get("last_status"),
        "last_vm_count":    existing.get("last_vm_count"),
    }
    _save_raw(data)


def load_all() -> list[dict]:
    """Return all credentials without passwords, sorted by host."""
    data = _load_raw()
    return sorted(
        [{k: v for k, v in e.items() if k != "password_enc"} for e in data.values()],
        key=lambda x: x.get("host", ""),
    )


def load(host: str) -> Optional[dict]:
    """Return one credential with decrypted password, or None."""
    data  = _load_raw()
    entry = data.get(host)
    if not entry:
        return None
    try:
        password = _cipher().decrypt(entry["password_enc"].encode()).decode()
    except (InvalidToken, Exception):
        password = ""
    return {**{k: v for k, v in entry.items() if k != "password_enc"}, "password": password}


def delete(host: str) -> None:
    data = _load_raw()
    data.pop(host, None)
    _save_raw(data)


def toggle(host: str) -> bool:
    """Toggle enabled state; returns new state."""
    data = _load_raw()
    if host not in data:
        return False
    data[host]["enabled"] = not data[host].get("enabled", True)
    _save_raw(data)
    return data[host]["enabled"]


def record_run(host: str, status: str, vm_count: int = 0) -> None:
    data = _load_raw()
    if host in data:
        data[host]["last_run"]      = datetime.now(timezone.utc).isoformat()
        data[host]["last_status"]   = status
        data[host]["last_vm_count"] = vm_count
        _save_raw(data)
