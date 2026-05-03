"""
config_store.py
---------------
Read and write non-sensitive runtime settings to/from the .env file.
Secrets (FLASK_SECRET, ENCRYPTION_KEY, DATABASE_URL) are never exposed
through this module — only PORT and FLASK_DEBUG are managed here.
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_ENV_FILE = Path(__file__).parent / ".env"

# Settings managed by the UI (safe to display / edit)
MANAGED_KEYS = {"PORT", "FLASK_DEBUG"}


def _read_lines() -> list[str]:
    if not _ENV_FILE.exists():
        return []
    with open(_ENV_FILE, "r", encoding="utf-8") as fh:
        return fh.readlines()


def load() -> dict:
    """Return all managed settings from .env as a plain dict."""
    result = {}
    for line in _read_lines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" in stripped:
            key, _, val = stripped.partition("=")
            key = key.strip()
            if key in MANAGED_KEYS:
                result[key] = val.strip()
    return result


def get(key: str, default: str = "") -> str:
    return load().get(key, default)


def save(updates: dict) -> bool:
    """
    Update or append managed key=value pairs in .env.
    Preserves all existing lines, comments, and unmanaged keys.
    Only keys listed in MANAGED_KEYS are accepted.
    """
    safe_updates = {k: v for k, v in updates.items() if k in MANAGED_KEYS}
    if not safe_updates:
        return True

    lines = _read_lines()
    written: set[str] = set()
    new_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue
        if "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in safe_updates:
                new_lines.append(f"{key}={safe_updates[key]}\n")
                written.add(key)
                continue
        new_lines.append(line)

    # Append keys that weren't in the file yet
    for key, val in safe_updates.items():
        if key not in written:
            new_lines.append(f"{key}={val}\n")

    try:
        _ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_ENV_FILE, "w", encoding="utf-8") as fh:
            fh.writelines(new_lines)
        logger.info("Updated .env: %s", list(safe_updates.keys()))
        return True
    except OSError as exc:
        logger.error("Failed to write .env: %s", exc)
        return False


def env_file_path() -> str:
    return str(_ENV_FILE)
