"""
asset_lookup.py
---------------
Checks VM IP addresses against the internal Asset Inventory API.

Strategy: fetch all asset IPs in two bulk calls (one for main assets,
one paginated for extended inventory), build a local {ip: label} map,
and cache it for 10 minutes. Lookups are then O(1) per IP with no extra
API calls during a MAC Lookup page render.
"""

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)

_CONFIG_PATH  = os.path.join(os.path.dirname(__file__), "cache", "asset_api_config.json")
_TIMEOUT      = 10   # seconds per HTTP call
_IP_CACHE_TTL = 600  # 10 minutes

_lock        = threading.Lock()
_token_state: dict = {}  # {token, expires_at}
_ip_state:    dict = {}  # {data: {ip: label}, expires_at}


# ── Encryption (reuses same ENCRYPTION_KEY as credential_store) ─────────────

def _fernet():
    key = os.environ.get("ENCRYPTION_KEY", "")
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception:
        return None


def _encrypt(text: str) -> str:
    enc = _fernet()
    return enc.encrypt(text.encode()).decode() if enc else text


def _decrypt(text: str) -> str:
    enc = _fernet()
    if not enc:
        return text
    try:
        return enc.decrypt(text.encode()).decode()
    except Exception:
        return text


# ── Config ───────────────────────────────────────────────────────────────────

def save_config(base_url: str, username: str, password: str) -> None:
    os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
    cfg = {
        "base_url": base_url.rstrip("/"),
        "username": username,
        "password": _encrypt(password) if password else "",
    }
    with open(_CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)
    with _lock:
        _token_state.clear()
        _ip_state.clear()


def load_config() -> dict:
    """Returns {base_url, username, password (decrypted)} or {}."""
    if not os.path.exists(_CONFIG_PATH):
        return {}
    try:
        with open(_CONFIG_PATH) as f:
            cfg = json.load(f)
        if cfg.get("password"):
            cfg["password"] = _decrypt(cfg["password"])
        return cfg
    except Exception:
        return {}


def load_config_safe() -> dict:
    """Config for templates — never includes the decrypted password."""
    cfg = load_config()
    cfg["has_password"] = bool(cfg.get("password"))
    cfg["password"] = ""
    return cfg


def is_configured() -> bool:
    cfg = load_config()
    return bool(cfg.get("base_url") and cfg.get("username"))


def invalidate_cache() -> None:
    with _lock:
        _ip_state.clear()


# ── JWT auth ─────────────────────────────────────────────────────────────────

def _get_token(cfg: dict) -> str | None:
    with _lock:
        if _token_state.get("token") and time.time() < _token_state.get("expires_at", 0):
            return _token_state["token"]

    url     = f"{cfg['base_url']}/api/auth/login"
    payload = json.dumps({"username": cfg["username"], "password": cfg["password"]}).encode()
    req     = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
        token = data.get("token")
        if not token:
            return None
        with _lock:
            _token_state["token"]      = token
            _token_state["expires_at"] = time.time() + 7 * 3600  # 1h before 8h TTL
        return token
    except Exception as exc:
        logger.warning("Asset API auth failed (%s): %s", cfg.get("base_url"), exc)
        return None


def _get(cfg: dict, path: str):
    """Authenticated GET. Retries once on 401. Returns parsed JSON or None."""
    for attempt in range(2):
        token = _get_token(cfg)
        if not token:
            return None
        req = urllib.request.Request(
            f"{cfg['base_url']}{path}",
            headers={"Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 401 and attempt == 0:
                with _lock:
                    _token_state.clear()
                continue
            logger.debug("Asset API HTTP %d for %s", exc.code, path)
            return None
        except Exception as exc:
            logger.debug("Asset API error for %s: %s", path, exc)
            return None
    return None


# ── Bulk IP fetch (cached) ────────────────────────────────────────────────────

def fetch_all_asset_ips() -> dict:
    """
    Returns {ip_lowercase: label} where label is one of:
      "Asset Inventory", "Ext. Asset Inventory", "Both"
    Returns {} if not configured or API is unreachable.
    Result is cached for 10 minutes.
    """
    with _lock:
        if _ip_state.get("data") is not None and time.time() < _ip_state.get("expires_at", 0):
            return _ip_state["data"]

    cfg = load_config()
    if not cfg.get("base_url") or not cfg.get("username"):
        return {}

    ip_sources: dict = {}  # ip → set of source labels

    # ── Main assets (all records, no pagination) ──
    data = _get(cfg, "/api/assets/report")
    if isinstance(data, dict):
        assets = data.get("assets", [])
    elif isinstance(data, list):
        assets = data
    else:
        assets = []
    for a in assets:
        ip = (a.get("ip_address") or "").strip().lower()
        if ip:
            ip_sources.setdefault(ip, set()).add("Asset Inventory")

    # ── Extended inventory (paginated) ──
    limit, page = 500, 1
    while True:
        data = _get(cfg, f"/api/extended-inventory?limit={limit}&page={page}")
        if not isinstance(data, dict):
            break
        items = data.get("items", [])
        if not items:
            break
        for item in items:
            ip = (item.get("ip_address") or "").strip().lower()
            if ip:
                ip_sources.setdefault(ip, set()).add("Ext. Asset Inventory")
        total = data.get("total", 0)
        if page * limit >= total:
            break
        page += 1

    result: dict = {}
    for ip, sources in ip_sources.items():
        if len(sources) == 2:
            result[ip] = "Both"
        else:
            result[ip] = next(iter(sources))

    with _lock:
        _ip_state["data"]       = result
        _ip_state["expires_at"] = time.time() + _IP_CACHE_TTL

    logger.info("Asset IP cache built: %d IPs from Asset Inventory + Ext. Asset Inventory", len(result))
    return result


def check_ips(ips: list[str]) -> str:
    """
    Given VM IP strings, returns the combined asset-list status:
    "Asset Inventory", "Ext. Asset Inventory", "Both", "—", or "" (not configured).
    """
    if not is_configured():
        return ""
    ip_map = fetch_all_asset_ips()
    found: set = set()
    for ip in ips:
        label = ip_map.get(ip.strip().lower())
        if label == "Both":
            found.update({"Asset Inventory", "Ext. Asset Inventory"})
        elif label:
            found.add(label)
    if not found:
        return "—"
    if len(found) == 2:
        return "Both"
    return next(iter(found))


# ── Test connection ───────────────────────────────────────────────────────────

def test_connection() -> tuple[bool, str]:
    cfg = load_config()
    if not cfg.get("base_url"):
        return False, "No API URL configured."
    with _lock:
        _token_state.clear()
    token = _get_token(cfg)
    if token:
        return True, f"Connected to {cfg['base_url']} successfully."
    return False, "Authentication failed — check the URL, username, and password."
