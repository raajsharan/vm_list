"""
scheduler.py
------------
APScheduler-based background scheduler for periodic VM discovery.
Imports of heavy modules are deferred inside _discover() to avoid
circular-import issues at startup.
"""

import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)

_sched       = BackgroundScheduler(daemon=True)
_active_lock = threading.Lock()
_active: set = set()    # hosts currently being discovered


# ---------------------------------------------------------------------------
# Internal discovery worker
# ---------------------------------------------------------------------------

def _discover(host: str) -> None:
    import credential_store
    import vmware_client
    import cache as cache_store
    import database

    with _active_lock:
        if host in _active:
            logger.info("Discovery for %s already running – skipping", host)
            return
        _active.add(host)

    try:
        cred = credential_store.load(host)
        if not cred:
            logger.warning("No credential found for %s", host)
            return

        logger.info("Starting discovery for %s", host)
        records = vmware_client.discover(
            host=cred["host"],
            username=cred["username"],
            password=cred["password"],
            port=cred.get("port", 443),
            verify_ssl=cred.get("verify_ssl", False),
        )
        cache_store.save(records, host)
        database.save_inventory(records, host)
        credential_store.record_run(host, "success", len(records))
        logger.info("Discovery for %s complete: %d VMs", host, len(records))

    except Exception as exc:
        label = type(exc).__name__
        short = str(exc)[:120]
        credential_store.record_run(host, f"{label}: {short}")
        logger.error("Discovery error for %s: %s", host, exc)

    finally:
        with _active_lock:
            _active.discard(host)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init() -> None:
    """Start the scheduler and load all enabled jobs from credential store."""
    if _sched.running:
        return
    _sched.start()
    logger.info("Background scheduler started")
    _sync_jobs()


def _sync_jobs() -> None:
    import credential_store
    existing = {j.id for j in _sched.get_jobs()}
    for cred in credential_store.load_all():
        host    = cred["host"]
        minutes = cred.get("interval_minutes", 60)
        if cred.get("enabled"):
            _sched.add_job(
                _discover,
                IntervalTrigger(minutes=minutes),
                id=host,
                args=[host],
                name=f"vm:{host}",
                replace_existing=True,
                misfire_grace_time=300,
            )
        elif host in existing:
            _sched.remove_job(host)


def upsert(host: str, interval_minutes: int, enabled: bool) -> None:
    """Add or update the scheduler job for a host."""
    if not _sched.running:
        return
    if enabled:
        _sched.add_job(
            _discover,
            IntervalTrigger(minutes=interval_minutes),
            id=host,
            args=[host],
            name=f"vm:{host}",
            replace_existing=True,
            misfire_grace_time=300,
        )
    else:
        _remove(host)


def remove(host: str) -> None:
    _remove(host)


def _remove(host: str) -> None:
    try:
        _sched.remove_job(host)
    except Exception:
        pass


def run_now(host: str) -> None:
    """Trigger an immediate discovery in a background thread."""
    threading.Thread(target=_discover, args=(host,), daemon=True).start()


def next_run(host: str) -> Optional[datetime]:
    job = _sched.get_job(host)
    return job.next_run_time if job else None


def active_hosts() -> frozenset:
    with _active_lock:
        return frozenset(_active)


def format_next_run(host: str) -> Optional[str]:
    dt = next_run(host)
    if dt is None:
        return None
    now   = datetime.now(timezone.utc)
    secs  = int((dt - now).total_seconds())
    if secs < 0:
        return "soon"
    if secs < 3600:
        return f"in {secs // 60}m"
    if secs < 86400:
        h, m = divmod(secs // 60, 60)
        return f"in {h}h {m}m" if m else f"in {h}h"
    return dt.strftime("%Y-%m-%d %H:%M UTC")
