"""
mac_lookup.py
-------------
Parse, store and index the MAC-to-IP spreadsheet uploaded via the Settings page.
Normalises every MAC format (Cisco dot-notation, colon, hyphen) to 12 lowercase
hex chars so cross-format comparison always works.
"""

import csv
import io
import json
import logging
import os
import re
from datetime import datetime

logger = logging.getLogger(__name__)

_BASE        = os.path.dirname(__file__)
_CACHE_DIR   = os.path.join(_BASE, "cache")
MAPPING_FILE = os.path.join(_CACHE_DIR, "mac_mapping.json")
META_FILE    = os.path.join(_CACHE_DIR, "mac_mapping_meta.json")


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
    "mac":          ["mac address", "mac_address", "macaddress", "mac", "mac addr"],
    "ip":           ["ip address", "ip_address", "ipaddress", "ip", "ip addr", "mapped ip"],
    "lan_segment":  ["lan segment", "lan_segment", "segment", "network", "subnet"],
    "vlan_group":   ["vlan group", "vlan_group", "vlan", "vlan name"],
    "data_retrieved": ["data retrieved", "date retrieved", "retrieved", "timestamp",
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
    Each normalised row contains: mac_raw, mac_norm, ip_address,
    lan_segment, vlan_group, data_retrieved.
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
        return [], {
            "uploaded_at": datetime.utcnow().isoformat() + "Z",
            "filename": filename,
            "row_count": 0,
        }

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
        "uploaded_at": datetime.utcnow().isoformat() + "Z",
        "filename":    filename,
        "row_count":   len(normalised),
        "total_rows":  len(raw_rows),
        "cols_detected": {
            "mac":  mac_col, "ip": ip_col, "lan": lan_col,
            "vlan": vlan_col, "data": data_col,
        },
    }
    return normalised, meta


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_mapping(rows: list[dict], meta: dict) -> None:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    try:
        with open(MAPPING_FILE, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2, default=str)
        with open(META_FILE, "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2, default=str)
        logger.info("Saved %d MAC mapping rows from %s", len(rows), meta.get("filename"))
    except OSError as exc:
        logger.warning("Could not save MAC mapping: %s", exc)


def load_mapping() -> list[dict]:
    if not os.path.exists(MAPPING_FILE):
        return []
    try:
        with open(MAPPING_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Could not load MAC mapping: %s", exc)
        return []


def load_meta() -> dict:
    if not os.path.exists(META_FILE):
        return {}
    try:
        with open(META_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def build_index(rows: list[dict]) -> dict[str, dict]:
    """Return {mac_norm: row} for O(1) lookups."""
    return {r["mac_norm"]: r for r in rows if r.get("mac_norm")}


def clear_mapping() -> None:
    for f in (MAPPING_FILE, META_FILE):
        try:
            os.remove(f)
        except FileNotFoundError:
            pass
