"""
notifier.py
-----------
Generates in-app notifications from discovery events. Notifications are stored
in PostgreSQL (database.add_notification) and surfaced to users as a popup the
next time they log in, plus on the Notifications page.

All functions are defensive: if the database or asset API is unavailable they
simply do nothing.
"""

import logging

import database

logger = logging.getLogger(__name__)


def discovery_failed(host: str, error: str) -> None:
    database.add_notification(
        "error", "discovery",
        f"Discovery failed for {host}: {error}",
        host=host,
    )


def _untracked_count(records: list[dict]) -> int:
    """How many VMs have at least one IP that is NOT in any asset inventory."""
    try:
        import asset_lookup as asset_api
        if not asset_api.is_configured():
            return 0
        ip_map = asset_api.fetch_all_asset_ips()
        if not ip_map:
            return 0
    except Exception as exc:
        logger.warning("Untracked-VM check skipped: %s", exc)
        return 0

    untracked = 0
    for rec in records:
        ips = rec.get("ips", []) or []
        if isinstance(ips, str):
            ips = [ips]
        real = [str(i).strip().lower() for i in ips
                if i and str(i).strip().lower() != "not available"]
        if not real:
            continue
        if not any(ip in ip_map for ip in real):
            untracked += 1
    return untracked


def after_discovery(host: str, records: list[dict]) -> None:
    """Raise notifications for: VMs not tracked in asset inventory, and
    drift (added/removed VMs) versus the previous snapshot."""
    if not database.is_configured():
        return

    # --- Untracked VMs (not present in any asset inventory) ---
    try:
        untracked = _untracked_count(records)
        if untracked:
            database.add_notification(
                "warning", "asset",
                f"{host}: {untracked} VM(s) are not in any asset inventory.",
                host=host,
            )
    except Exception as exc:
        logger.warning("Untracked notification failed for %s: %s", host, exc)

    # --- Drift versus previous snapshot ---
    try:
        drift = database.compute_drift_for_host(host)
        if drift:
            added   = len(drift["added"])
            removed = len(drift["removed"])
            changed = len(drift["changed"])
            if added or removed:
                bits = []
                if added:
                    bits.append(f"{added} new")
                if removed:
                    bits.append(f"{removed} removed")
                if changed:
                    bits.append(f"{changed} changed")
                level = "warning" if removed else "info"
                database.add_notification(
                    level, "drift",
                    f"{host}: inventory drift — " + ", ".join(bits) + ".",
                    host=host,
                )
    except Exception as exc:
        logger.warning("Drift notification failed for %s: %s", host, exc)
