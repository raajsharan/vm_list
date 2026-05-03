"""
data_processor.py
-----------------
Normalises raw VM dicts into display-ready structures.
Keeps list fields as pipe-separated strings for table rendering
while preserving the original lists for JSON/CSV export.
"""

from typing import Any


_UNKNOWN = "Not Available"


def _join(value: Any, sep: str = " | ") -> str:
    """Join a list to a display string, or return the value as-is."""
    if isinstance(value, list):
        cleaned = [str(v) for v in value if v and v != _UNKNOWN]
        return sep.join(cleaned) if cleaned else _UNKNOWN
    return str(value) if value else _UNKNOWN


def normalise_for_display(records: list[dict]) -> list[dict]:
    """
    Convert raw inventory records into flat dicts suitable for
    Jinja2 table rendering (lists become pipe-separated strings).
    source_host / discovered_at are passed through when present.
    """
    display = []
    for rec in records:
        display.append({
            # consolidated-view extras (empty string when not present)
            "source_host":     rec.get("source_host", ""),
            "discovered_at":   rec.get("discovered_at", ""),
            "name":            rec.get("name", _UNKNOWN),
            "hostname":        rec.get("hostname", _UNKNOWN),
            "ip_addresses":    _join(rec.get("ips", [_UNKNOWN])),
            "esxi_host_name":  rec.get("esxi_host_name", _UNKNOWN),
            "esxi_host_ip":    rec.get("esxi_host_ip", _UNKNOWN),
            "os_type":         rec.get("os_type", _UNKNOWN),
            "os_version":      rec.get("os_version", _UNKNOWN),
            "mac_addresses":   _join(rec.get("macs", [_UNKNOWN])),
            "created_date":    rec.get("created_date", _UNKNOWN),
            "power_state":     rec.get("power_state", _UNKNOWN),
            "tools_status":    rec.get("tools_status", _UNKNOWN),
        })
    return display


def to_csv_rows_consolidated(records: list[dict]) -> list[dict]:
    """CSV export for the consolidated dashboard (includes Source Host column)."""
    rows = []
    for rec in records:
        rows.append({
            "Source Host":      rec.get("source_host", ""),
            "Discovered At":    rec.get("discovered_at", ""),
            "VM Name":          rec.get("name", _UNKNOWN),
            "Hostname":         rec.get("hostname", _UNKNOWN),
            "IP Addresses":     _join(rec.get("ips", [_UNKNOWN]), "; "),
            "ESXi Host Name":   rec.get("esxi_host_name", _UNKNOWN),
            "ESXi Host IP":     rec.get("esxi_host_ip", _UNKNOWN),
            "OS Type":          rec.get("os_type", _UNKNOWN),
            "OS Version":       rec.get("os_version", _UNKNOWN),
            "MAC Addresses":    _join(rec.get("macs", [_UNKNOWN]), "; "),
            "Created Date":     rec.get("created_date", _UNKNOWN),
            "Power State":      rec.get("power_state", _UNKNOWN),
            "VMware Tools":     rec.get("tools_status", _UNKNOWN),
        })
    return rows


def to_csv_rows(records: list[dict]) -> list[dict]:
    """
    Flatten records for CSV export.
    Lists are joined with semicolons for spreadsheet compatibility.
    """
    rows = []
    for rec in records:
        rows.append({
            "VM Name":          rec.get("name", _UNKNOWN),
            "Hostname":         rec.get("hostname", _UNKNOWN),
            "IP Addresses":     _join(rec.get("ips", [_UNKNOWN]), "; "),
            "ESXi Host Name":   rec.get("esxi_host_name", _UNKNOWN),
            "ESXi Host IP":     rec.get("esxi_host_ip", _UNKNOWN),
            "OS Type":          rec.get("os_type", _UNKNOWN),
            "OS Version":       rec.get("os_version", _UNKNOWN),
            "MAC Addresses":    _join(rec.get("macs", [_UNKNOWN]), "; "),
            "Created Date":     rec.get("created_date", _UNKNOWN),
            "Power State":      rec.get("power_state", _UNKNOWN),
            "VMware Tools":     rec.get("tools_status", _UNKNOWN),
        })
    return rows
