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

_CONFIG_PATH     = os.path.join(os.path.dirname(__file__), "cache", "asset_api_config.json")
_TIMEOUT         = 10   # seconds per HTTP call
_IP_CACHE_TTL    = 600  # 10 minutes (successful fetch)
_IP_CACHE_TTL_ERR = 60  # 1 minute retry after failed/empty fetch

_lock        = threading.Lock()
_token_state: dict = {}  # {token, expires_at}
_ip_state:    dict = {}  # {data, expires_at, main_count, ext_count, fetched_at, error}
_full_state:  dict = {}  # {data, expires_at}   data = {ip: full_record_dict}
_status_state: dict = {}  # {data, expires_at}   data = {lowercased_name: id}
_refresh_lock = threading.Lock()  # serializes background refresh attempts


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
        _status_state.clear()


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
        _full_state.clear()
        _status_state.clear()


def get_cache_info() -> dict:
    """Returns diagnostic info about the current cache state."""
    with _lock:
        if not _ip_state:
            return {"status": "empty", "count": 0}
        data = _ip_state.get("data")
        if data is None:
            return {"status": "empty", "count": 0}
        expires_at  = _ip_state.get("expires_at", 0)
        fetched_at  = _ip_state.get("fetched_at", 0)
        main_count  = _ip_state.get("main_count", 0)
        ext_count   = _ip_state.get("ext_count", 0)
        error       = _ip_state.get("error", "")
        ttl_left    = max(0, int(expires_at - time.time()))
        return {
            "status":      "ok" if data else ("error" if error else "empty"),
            "count":       len(data),
            "main_count":  main_count,
            "ext_count":   ext_count,
            "fetched_at":  fetched_at,
            "ttl_left":    ttl_left,
            "error":       error,
        }


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
            logger.warning("Asset API login succeeded but no token in response from %s", cfg.get("base_url"))
            return None
        with _lock:
            _token_state["token"]      = token
            _token_state["expires_at"] = time.time() + 7 * 3600  # 1h before 8h TTL
        return token
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode()[:200]
        except Exception:
            pass
        logger.warning("Asset API auth HTTP %d from %s: %s", exc.code, cfg.get("base_url"), body)
        return None
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
                logger.info("Asset API 401 on %s — refreshing token", path)
                with _lock:
                    _token_state.clear()
                continue
            body = ""
            try:
                body = exc.read().decode()[:200]
            except Exception:
                pass
            logger.warning("Asset API HTTP %d for %s: %s", exc.code, path, body)
            return None
        except Exception as exc:
            logger.warning("Asset API request failed for %s: %s", path, exc)
            return None
    return None


# ── Bulk IP fetch (cached) ────────────────────────────────────────────────────

def fetch_all_asset_ips() -> dict:
    """
    Returns {ip_lowercase: label} where label is one of:
      "Asset Inventory", "Ext. Asset Inventory", "Both"
    Returns {} if not configured or API is unreachable.
    Stale-while-revalidate: when cache is stale but present, returns the
    stale data immediately and triggers a background refresh — page renders
    stay fast even as the cache expires.
    """
    now = time.time()
    with _lock:
        data = _ip_state.get("data")
        exp  = _ip_state.get("expires_at", 0)
        if data is not None:
            if now < exp:
                return data
            # stale but present — serve immediately, refresh in background
            threading.Thread(target=_refresh_ip_cache, daemon=True).start()
            return data

    cfg = load_config()
    if not cfg.get("base_url") or not cfg.get("username"):
        return {}

    ip_sources: dict = {}  # ip → set of source labels
    main_count = 0
    ext_count  = 0
    error_msg  = ""

    # ── Main assets (all records, no pagination) ──
    data = _get(cfg, "/api/assets/report")
    if isinstance(data, list):
        assets = data
    elif isinstance(data, dict):
        assets = data.get("assets", [])
    else:
        assets = []
        error_msg = "Failed to fetch main assets — check API URL and credentials"
        logger.warning("Asset API: /api/assets/report returned unexpected type %s", type(data))

    for a in assets:
        ip = (a.get("ip_address") or "").strip().lower()
        if ip:
            ip_sources.setdefault(ip, set()).add("Asset Inventory")
            main_count += 1

    logger.info("Asset API: loaded %d IPs from /api/assets/report", main_count)

    # ── Extended inventory (paginated) ──
    limit, page = 500, 1
    while True:
        data = _get(cfg, f"/api/extended-inventory?limit={limit}&page={page}")
        if not isinstance(data, dict):
            if page == 1 and data is None:
                logger.warning("Asset API: /api/extended-inventory returned no data on page 1")
            break
        items = data.get("items", [])
        if not items:
            break
        for item in items:
            ip = (item.get("ip_address") or "").strip().lower()
            if ip:
                ip_sources.setdefault(ip, set()).add("Ext. Asset Inventory")
                ext_count += 1
        total = data.get("total", 0)
        if page * limit >= total:
            break
        page += 1

    logger.info("Asset API: loaded %d IPs from /api/extended-inventory", ext_count)

    result: dict = {}
    for ip, sources in ip_sources.items():
        if len(sources) == 2:
            result[ip] = "Both"
        else:
            result[ip] = next(iter(sources))

    # Use shorter TTL when nothing was fetched so we retry sooner
    ttl = _IP_CACHE_TTL if result else _IP_CACHE_TTL_ERR

    with _lock:
        _ip_state["data"]       = result
        _ip_state["expires_at"] = time.time() + ttl
        _ip_state["fetched_at"] = time.time()
        _ip_state["main_count"] = main_count
        _ip_state["ext_count"]  = ext_count
        _ip_state["error"]      = error_msg

    logger.info(
        "Asset IP cache: %d unique IPs (%d main + %d ext), TTL %ds",
        len(result), main_count, ext_count, ttl,
    )
    return result


def _refresh_ip_cache() -> None:
    """Background refresh: forces a fresh fetch_all_asset_ips() call.
    Held by _refresh_lock to avoid stampedes if several requests are stale
    at the same time."""
    if not _refresh_lock.acquire(blocking=False):
        return
    try:
        with _lock:
            # Force the synchronous fetch path by expiring the cache locally
            _ip_state["expires_at"] = 0
        fetch_all_asset_ips()
    except Exception as exc:
        logger.warning("Background asset-IP cache refresh failed: %s", exc)
    finally:
        _refresh_lock.release()


def _refresh_full_cache() -> None:
    if not _refresh_lock.acquire(blocking=False):
        return
    try:
        with _lock:
            _full_state["expires_at"] = 0
        fetch_assets_full()
    except Exception as exc:
        logger.warning("Background full-asset cache refresh failed: %s", exc)
    finally:
        _refresh_lock.release()


def warm_caches_async() -> None:
    """Kick off a background fetch on app startup so the first user request
    doesn't pay the cold-cache cost. Safe to call when the API is not yet
    configured — it will just return without doing work."""
    if not is_configured():
        logger.info("Asset API not configured — skipping cache warmup")
        return

    def _warm():
        try:
            logger.info("Warming asset IP/full caches in background…")
            fetch_all_asset_ips()
            fetch_assets_full()
            logger.info("Asset cache warmup complete.")
        except Exception as exc:
            logger.warning("Asset cache warmup failed: %s", exc)

    threading.Thread(target=_warm, daemon=True).start()


# ── Test connection ───────────────────────────────────────────────────────────

def test_connection() -> tuple[bool, str]:
    """Tests auth AND data access. Returns (success, message)."""
    cfg = load_config()
    if not cfg.get("base_url"):
        return False, "No API URL configured."

    # Force fresh auth
    with _lock:
        _token_state.clear()
    token = _get_token(cfg)
    if not token:
        return False, "Authentication failed — check the URL, username, and password."

    # Test data access on main assets
    data = _get(cfg, "/api/assets/report")
    if isinstance(data, list):
        asset_count = len(data)
    elif isinstance(data, dict):
        asset_count = len(data.get("assets", []))
    else:
        return False, (
            f"Authenticated OK, but /api/assets/report returned an error. "
            "Check that the configured user has access to the Asset List."
        )

    # Test ext inventory access
    ext_data = _get(cfg, "/api/extended-inventory?limit=1&page=1")
    ext_total = ext_data.get("total", "?") if isinstance(ext_data, dict) else "error"

    # Invalidate IP cache so next MAC Lookup load fetches fresh data
    with _lock:
        _ip_state.clear()

    return True, (
        f"Connected to {cfg['base_url']}. "
        f"Asset Inventory: {asset_count} record(s). "
        f"Ext. Asset Inventory: {ext_total} record(s)."
    )


# ── Full asset record fetch (for asset-details page) ─────────────────────────

def fetch_assets_full() -> dict:
    """
    Returns {ip_lowercase: record_dict} for every known asset.
    Each record_dict has a 'source' key: "Asset Inventory", "Ext. Asset Inventory", or "Both".
    Stale-while-revalidate: returns stale data immediately and refreshes in
    the background. Warms the IP-only cache as a side-effect.
    """
    now = time.time()
    with _lock:
        data = _full_state.get("data")
        exp  = _full_state.get("expires_at", 0)
        if data is not None:
            if now < exp:
                return data
            threading.Thread(target=_refresh_full_cache, daemon=True).start()
            return data

    cfg = load_config()
    if not cfg.get("base_url") or not cfg.get("username"):
        return {}

    result: dict = {}
    main_count = 0
    ext_count  = 0

    # ── Main asset inventory ──
    data = _get(cfg, "/api/assets/report")
    if isinstance(data, list):
        assets = data
    elif isinstance(data, dict):
        assets = data.get("assets", [])
    else:
        assets = []

    for a in assets:
        ip = (a.get("ip_address") or "").strip().lower()
        if ip:
            result[ip] = {**a, "source": "Asset Inventory"}
            main_count += 1

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
                if ip in result:
                    result[ip]["source"] = "Both"
                    for k, v in item.items():
                        if v and not result[ip].get(k):
                            result[ip][k] = v
                else:
                    result[ip] = {**item, "source": "Ext. Asset Inventory"}
                ext_count += 1
        total = data.get("total", 0)
        if page * limit >= total:
            break
        page += 1

    ttl = _IP_CACHE_TTL if result else _IP_CACHE_TTL_ERR

    with _lock:
        _full_state["data"]       = result
        _full_state["expires_at"] = time.time() + ttl
        # Warm the IP-only cache if stale
        if not (_ip_state.get("data") and time.time() < _ip_state.get("expires_at", 0)):
            ip_map: dict = {}
            for ip, rec in result.items():
                src = rec.get("source", "")
                ip_map[ip] = "Both" if src == "Both" else ("Ext. Asset Inventory" if "Ext" in src else "Asset Inventory")
            _ip_state.update({
                "data":       ip_map,
                "expires_at": time.time() + ttl,
                "main_count": main_count,
                "ext_count":  ext_count,
                "fetched_at": time.time(),
                "error":      "",
            })

    logger.info("Asset full-record cache: %d records (%d main + %d ext)", len(result), main_count, ext_count)
    return result


def _post(cfg: dict, path: str, payload: dict):
    """Authenticated POST to the asset API. Returns parsed JSON or None."""
    token = _get_token(cfg)
    if not token:
        return None
    req = urllib.request.Request(
        f"{cfg['base_url']}{path}",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization":  f"Bearer {token}",
            "Content-Type":   "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            try:
                return json.loads(resp.read())
            except Exception:
                return {"status": "ok"}
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode()[:400]
        except Exception:
            pass
        logger.warning("Asset API POST HTTP %d for %s: %s", exc.code, path, body)
        return None
    except Exception as exc:
        logger.warning("Asset API POST failed for %s: %s", path, exc)
        return None


def _get_server_status_id(cfg: dict, name: str) -> int | None:
    """
    Resolve a server_status row name (e.g. "Alive") to its id via the
    /api/dropdowns/server_status endpoint. Cached for 10 min.
    """
    if not name:
        return None
    key = name.strip().lower()
    with _lock:
        data = _status_state.get("data")
        if data is not None and time.time() < _status_state.get("expires_at", 0):
            return data.get(key)

    rows = _get(cfg, "/api/dropdowns/server_status")
    if not isinstance(rows, list):
        return None
    name_to_id = {
        str(r.get("name", "")).strip().lower(): r.get("id")
        for r in rows if r.get("name") and r.get("id") is not None
    }
    with _lock:
        _status_state["data"]       = name_to_id
        _status_state["expires_at"] = time.time() + _IP_CACHE_TTL
    return name_to_id.get(key)


# Map Flask-side entry keys → asset_invent backend body keys
_EXT_KEY_MAP = {
    "ip_address":  "ip_address",
    "asset_name":  "asset_name",
    "vm_name":     "vm_name",
    "os_hostname": "os_hostname",
    "hostname":    "os_hostname",   # legacy alias
    "mac_address": "mac_address",
    "hosted_ip":   "hosted_ip",
    "host_ip":     "hosted_ip",     # alias
    "source_host": "hosted_ip",     # alias used by Asset Details form
}


def add_to_ext_inventory(entries: list[dict]) -> tuple[int, int, list[str]]:
    """
    POST each entry to /api/extended-inventory.

    Recognised entry keys (all optional except ip_address):
      ip_address, asset_name, vm_name, os_hostname (or hostname),
      mac_address, hosted_ip (or host_ip / source_host).

    Each entry is also stamped with server_status_id resolved from "Alive"
    via /api/dropdowns/server_status.

    Returns (success_count, fail_count, error_messages).
    Invalidates both caches on any success.
    """
    cfg = load_config()
    if not cfg.get("base_url"):
        return 0, len(entries), ["Asset API not configured."]

    alive_id = _get_server_status_id(cfg, "Alive")

    success = 0
    fail    = 0
    errors: list[str] = []

    for entry in entries:
        # Translate aliases to the canonical asset_invent body keys
        payload: dict = {}
        for k, v in entry.items():
            if not v:
                continue
            canonical = _EXT_KEY_MAP.get(k, k)
            # First non-empty value wins (preserves explicit fields over aliases)
            payload.setdefault(canonical, v)
        if alive_id is not None:
            payload["server_status_id"] = alive_id
        result  = _post(cfg, "/api/extended-inventory", payload)
        if result is not None:
            success += 1
        else:
            fail += 1
            errors.append(f"Failed to add {entry.get('ip_address', '?')}")

    if success:
        with _lock:
            _ip_state.clear()
            _full_state.clear()
        logger.info("Asset caches cleared after adding %d entries to Ext. Asset Inventory", success)

    return success, fail, errors
