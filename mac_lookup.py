"""
mac_lookup.py
-------------
Parse, store and index one or more MAC-to-IP mapping spreadsheets.
Each uploaded file is stored independently under cache/mac_mappings/.
The combined index from all files is used for lookups.
"""

import csv
import io
import json
import logging
import os
import re
import secrets
from datetime import datetime

logger = logging.getLogger(__name__)

_BASE         = os.path.dirname(__file__)
_CACHE_DIR    = os.path.join(_BASE, "cache")
_MAPPINGS_DIR = os.path.join(_CACHE_DIR, "mac_mappings")

# Legacy single-file paths (kept only for migration)
_LEGACY_DATA = os.path.join(_CACHE_DIR, "mac_mapping.json")
_LEGACY_META = os.path.join(_CACHE_DIR, "mac_mapping_meta.json")


# ---------------------------------------------------------------------------
# MAC normalisation
# ---------------------------------------------------------------------------

def normalize_mac(mac: str) -> str:
    """Strip all separators, lowercase. Returns 12-char hex string or ''."""
    hexonly = re.sub(r"[^0-9a-fA-F]", "", mac or "")
    return hexonly.lower() if len(hexonly) == 12 else ""


# ---------------------------------------------------------------------------
# Column auto-detection
# ---------------------------------------------------------------------------

_COL_ALIASES: dict[str, list[str]] = {
    "mac":           ["mac address", "mac_address", "macaddress", "mac", "mac addr"],
    "ip":            ["ip address", "ip_address", "ipaddress", "ip", "ip addr", "mapped ip"],
    "lan_segment":   ["lan segment", "lan_segment", "segment", "network", "subnet"],
    "vlan_group":    ["vlan group", "vlan_group", "vlan", "vlan name"],
    "data_retrieved":["data retrieved", "date retrieved", "retrieved", "timestamp",
                      "date", "last updated", "updated"],
}


def _find_col(headers: list[str], key: str) -> str | None:
    aliases = _COL_ALIASES.get(key, [])
    for h in headers:
        if h.lower().strip() in aliases:
            return h
    return None


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_file(file_stream) -> tuple[list[dict], dict]:
    """
    Parse an uploaded .xlsx or .csv file.
    Returns (normalised_rows, meta_dict).
    """
    filename = getattr(file_stream, "filename", "") or ""
    content  = file_stream.read()
    raw_rows: list[dict] = []

    if filename.lower().endswith(".csv"):
        text = content.decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            raw_rows.append({k: (v or "").strip() for k, v in row.items()})
    else:
        try:
            import openpyxl
        except ImportError as exc:
            raise RuntimeError("openpyxl is required to parse .xlsx files. "
                               "Run: pip install openpyxl") from exc
        wb = openpyxl.load_workbook(io.BytesIO(content), read_only=True, data_only=True)
        ws = wb.active
        headers: list[str] | None = None
        for xl_row in ws.iter_rows(values_only=True):
            if all(v is None for v in xl_row):
                continue
            if headers is None:
                headers = [
                    str(h).strip() if h is not None else f"col_{i}"
                    for i, h in enumerate(xl_row)
                ]
                continue
            raw_rows.append({
                headers[i]: str(v).strip() if v is not None else ""
                for i, v in enumerate(xl_row)
                if i < len(headers)
            })
        wb.close()

    if not raw_rows:
        return [], {"uploaded_at": datetime.utcnow().isoformat() + "Z",
                    "filename": filename, "row_count": 0}

    all_headers = list(raw_rows[0].keys())
    mac_col  = _find_col(all_headers, "mac")
    ip_col   = _find_col(all_headers, "ip")
    lan_col  = _find_col(all_headers, "lan_segment")
    vlan_col = _find_col(all_headers, "vlan_group")
    data_col = _find_col(all_headers, "data_retrieved")

    normalised: list[dict] = []
    for row in raw_rows:
        mac_raw = row.get(mac_col, "") if mac_col else ""
        if not mac_raw:
            continue
        norm = normalize_mac(mac_raw)
        if not norm:
            continue
        normalised.append({
            "mac_raw":        mac_raw,
            "mac_norm":       norm,
            "ip_address":     (row.get(ip_col,   "") if ip_col   else ""),
            "lan_segment":    (row.get(lan_col,  "") if lan_col  else ""),
            "vlan_group":     (row.get(vlan_col, "") if vlan_col else ""),
            "data_retrieved": (row.get(data_col, "") if data_col else ""),
        })

    meta = {
        "uploaded_at":  datetime.utcnow().isoformat() + "Z",
        "filename":     filename,
        "row_count":    len(normalised),
        "total_rows":   len(raw_rows),
        "cols_detected": {
            "mac": mac_col, "ip": ip_col, "lan": lan_col,
            "vlan": vlan_col, "data": data_col,
        },
    }
    return normalised, meta


# ---------------------------------------------------------------------------
# Multi-file persistence
# ---------------------------------------------------------------------------

def _ensure_dir() -> None:
    os.makedirs(_MAPPINGS_DIR, exist_ok=True)


def _new_file_id() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S") + "_" + secrets.token_hex(3)


def _file_path(file_id: str) -> str:
    return os.path.join(_MAPPINGS_DIR, f"{file_id}.json")


def _migrate_legacy() -> None:
    """Move old single-file mapping into the multi-file store (runs once)."""
    if not os.path.exists(_LEGACY_DATA):
        return
    try:
        with open(_LEGACY_DATA, "r", encoding="utf-8") as fh:
            rows = json.load(fh)
        meta: dict = {}
        if os.path.exists(_LEGACY_META):
            with open(_LEGACY_META, "r", encoding="utf-8") as fh:
                meta = json.load(fh)
        if rows:
            fid = _new_file_id()
            meta.setdefault("filename",    "legacy_mapping.json")
            meta.setdefault("uploaded_at", datetime.utcnow().isoformat() + "Z")
            meta.setdefault("row_count",   len(rows))
            _ensure_dir()
            payload = dict(meta)
            payload["id"]   = fid
            payload["rows"] = rows
            with open(_file_path(fid), "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, default=str)
            logger.info("Migrated legacy MAC mapping (%d rows) to id=%s", len(rows), fid)
        os.remove(_LEGACY_DATA)
        if os.path.exists(_LEGACY_META):
            os.remove(_LEGACY_META)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Legacy MAC mapping migration failed: %s", exc)


def save_mapping_file(rows: list[dict], meta: dict) -> str:
    """Save a new mapping file. Returns the generated file_id."""
    _ensure_dir()
    _migrate_legacy()
    fid = _new_file_id()
    payload = dict(meta)
    payload["id"]   = fid
    payload["rows"] = rows
    try:
        with open(_file_path(fid), "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
        logger.info("Saved MAC mapping file id=%s (%d rows) from %s",
                    fid, len(rows), meta.get("filename"))
    except OSError as exc:
        logger.warning("Could not save MAC mapping file: %s", exc)
    return fid


def list_mapping_files() -> list[dict]:
    """
    Return meta for all stored mapping files (no rows), newest first.
    Triggers legacy migration on first call.
    """
    _migrate_legacy()
    if not os.path.exists(_MAPPINGS_DIR):
        return []
    files = []
    for fname in os.listdir(_MAPPINGS_DIR):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(_MAPPINGS_DIR, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            files.append({
                "id":            data.get("id", fname[:-5]),
                "filename":      data.get("filename", fname),
                "uploaded_at":   data.get("uploaded_at", ""),
                "row_count":     data.get("row_count", 0),
                "cols_detected": data.get("cols_detected", {}),
            })
        except (OSError, json.JSONDecodeError):
            pass
    return sorted(files, key=lambda x: x["uploaded_at"], reverse=True)


def load_all_rows() -> list[dict]:
    """Load and combine rows from every stored mapping file."""
    _migrate_legacy()
    if not os.path.exists(_MAPPINGS_DIR):
        return []
    all_rows: list[dict] = []
    for fname in os.listdir(_MAPPINGS_DIR):
        if not fname.endswith(".json"):
            continue
        fpath = os.path.join(_MAPPINGS_DIR, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            all_rows.extend(data.get("rows", []))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not read MAC mapping %s: %s", fname, exc)
    return all_rows


def delete_mapping_file(file_id: str) -> bool:
    """Delete a specific mapping file. Returns True if deleted."""
    path = _file_path(file_id)
    try:
        os.remove(path)
        logger.info("Deleted MAC mapping file id=%s", file_id)
        return True
    except FileNotFoundError:
        return False


def clear_all_mappings() -> int:
    """Delete all mapping files. Returns count of files removed."""
    if not os.path.exists(_MAPPINGS_DIR):
        return 0
    count = 0
    for fname in os.listdir(_MAPPINGS_DIR):
        if fname.endswith(".json"):
            try:
                os.remove(os.path.join(_MAPPINGS_DIR, fname))
                count += 1
            except OSError:
                pass
    for f in (_LEGACY_DATA, _LEGACY_META):
        try:
            os.remove(f)
        except FileNotFoundError:
            pass
    return count


def build_index(rows: list[dict]) -> dict[str, dict]:
    """Return {mac_norm: row} for O(1) lookups. First entry wins on duplicates."""
    index: dict[str, dict] = {}
    for r in rows:
        norm = r.get("mac_norm")
        if norm and norm not in index:
            index[norm] = r
    return index


# ---------------------------------------------------------------------------
# Backward-compat shims (used by old routes that referenced load_mapping /
# load_meta / save_mapping / clear_mapping)
# ---------------------------------------------------------------------------

def load_mapping() -> list[dict]:
    return load_all_rows()

def load_meta() -> dict:
    files = list_mapping_files()
    return files[0] if files else {}

def save_mapping(rows: list[dict], meta: dict) -> None:
    save_mapping_file(rows, meta)

def clear_mapping() -> None:
    clear_all_mappings()
