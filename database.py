"""
database.py
-----------
Simple SQLAlchemy support for persisting discovered VM records.
Uses DATABASE_URL from the environment to connect to PostgreSQL.
"""

import json
import logging
import urllib.parse
from datetime import datetime
from typing import Optional
from cryptography.fernet import Fernet

import os
from sqlalchemy import (
    Column, DateTime, Integer, String, Text, create_engine,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base, sessionmaker

logger = logging.getLogger(__name__)
Base = declarative_base()
SessionLocal = None
engine = None

# Encryption key for credentials
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if ENCRYPTION_KEY:
    cipher = Fernet(ENCRYPTION_KEY.encode())
else:
    logger.warning("ENCRYPTION_KEY not set; credential encryption disabled.")
    cipher = None


def _encrypt(value: str) -> str:
    if cipher and value:
        return cipher.encrypt(value.encode()).decode()
    return value


def _decrypt(value: str) -> str:
    if cipher and value:
        return cipher.decrypt(value.encode()).decode()
    return value


def _to_text(value):
    if value is None:
        return None
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return str(value)


def _from_text(value):
    if value is None:
        return None
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


class VmInventoryRecord(Base):
    __tablename__ = "vm_inventory"

    id = Column(Integer, primary_key=True, autoincrement=True)
    discovered_at = Column(DateTime, nullable=False)
    source_host = Column(String(255), nullable=False)
    vm_name = Column(String(255), nullable=False)
    hostname = Column(String(255))
    ip_addresses = Column(Text)
    esxi_host_name = Column(String(255))
    esxi_host_ip = Column(String(255))
    os_type = Column(String(255))
    os_version = Column(Text)
    mac_addresses = Column(Text)
    created_date = Column(String(64))
    power_state = Column(String(64))
    tools_status = Column(String(64))


class VmAssetEdit(Base):
    __tablename__ = "vm_asset_edits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_host = Column(String(255), nullable=False)
    vm_name = Column(String(255), nullable=False)
    asset_name = Column(String(255))
    hostname = Column(String(255))
    ip_address = Column(String(255))
    os_type = Column(String(255))
    os_version = Column(Text)
    updated_at = Column(DateTime)


class CredentialRecord(Base):
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host = Column(String(255), nullable=False, unique=True)
    username = Column(String(255), nullable=False)
    password_encrypted = Column(Text, nullable=False)
    port = Column(Integer, default=443)
    verify_ssl = Column(String(5), default="false")
    last_discovery = Column(DateTime)
    enabled = Column(String(5), default="true")


class SchedulerRecord(Base):
    __tablename__ = "scheduler"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(255), nullable=False, unique=True)
    host = Column(String(255), nullable=False)
    interval_minutes = Column(Integer, default=60)
    next_run = Column(DateTime)
    enabled = Column(String(5), default="true")


def build_url_from_env() -> Optional[str]:
    """
    Build a SQLAlchemy/psycopg URL from individual DB_* env vars, percent-encoding
    the user/password so special characters like '@' or ':' are safe.

    Returns None if the required vars are not set.
    """
    user     = os.environ.get("DB_USER")
    password = os.environ.get("DB_PASSWORD", "")
    host     = os.environ.get("DB_HOST", "localhost")
    port     = os.environ.get("DB_PORT", "5432")
    name     = os.environ.get("DB_NAME")
    if not user or not name:
        return None
    u = urllib.parse.quote(user, safe="")
    p = urllib.parse.quote(password, safe="")
    return f"postgresql+psycopg://{u}:{p}@{host}:{port}/{name}"


def init_app(database_url: Optional[str]):
    global engine, SessionLocal
    # Prefer the explicit DATABASE_URL (back-compat); otherwise build from DB_*.
    if not database_url:
        database_url = build_url_from_env()
    if not database_url:
        logger.info("Database not configured (set DB_HOST/DB_NAME/DB_USER/DB_PASSWORD); persistence disabled.")
        return

    try:
        engine = create_engine(database_url, echo=False, future=True)
        SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        Base.metadata.create_all(engine)
        logger.info("Database initialized for %s", database_url)
    except SQLAlchemyError as exc:
        engine = None
        SessionLocal = None
        logger.exception("Failed to initialize database: %s", exc)


def save_inventory(records: list[dict], source_host: str):
    if SessionLocal is None:
        logger.info("Database persistence skipped: no database configured.")
        return

    session = SessionLocal()
    # One shared timestamp per discovery batch — the "latest snapshot" queries
    # below match all rows from a batch by equality on this column, so every
    # row in a single save_inventory call must carry the same discovered_at.
    batch_dt = datetime.utcnow()
    try:
        for record in records:
            vm = VmInventoryRecord(
                discovered_at=batch_dt,
                source_host=source_host,
                vm_name=_to_text(record.get("name")),
                hostname=_to_text(record.get("hostname")),
                ip_addresses=_to_text(record.get("ips")),
                esxi_host_name=_to_text(record.get("esxi_host_name")),
                esxi_host_ip=_to_text(record.get("esxi_host_ip")),
                os_type=_to_text(record.get("os_type")),
                os_version=_to_text(record.get("os_version")),
                mac_addresses=_to_text(record.get("macs")),
                created_date=_to_text(record.get("created_date")),
                power_state=_to_text(record.get("power_state")),
                tools_status=_to_text(record.get("tools_status")),
            )
            session.add(vm)
        session.commit()
        logger.info("Saved %d VM records to the database for %s.", len(records), source_host)
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Failed to save VM inventory to database: %s", exc)
    finally:
        session.close()


def _row_to_dict(row: VmInventoryRecord, include_source: bool = False) -> dict:
    d = {
        "name":           _from_text(row.vm_name)        or "Not Available",
        "hostname":       _from_text(row.hostname)        or "Not Available",
        "ips":            _from_text(row.ip_addresses)    or ["Not Available"],
        "esxi_host_name": _from_text(row.esxi_host_name)  or "Not Available",
        "esxi_host_ip":   _from_text(row.esxi_host_ip)    or "Not Available",
        "os_type":        _from_text(row.os_type)         or "Not Available",
        "os_version":     _from_text(row.os_version)      or "Not Available",
        "macs":           _from_text(row.mac_addresses)   or ["Not Available"],
        "created_date":   _from_text(row.created_date)    or "Not Available",
        "power_state":    _from_text(row.power_state)     or "unknown",
        "tools_status":   _from_text(row.tools_status)    or "Not Available",
    }
    if include_source:
        d["source_host"]   = row.source_host or ""
        d["discovered_at"] = (
            row.discovered_at.strftime("%Y-%m-%d %H:%M UTC")
            if row.discovered_at else ""
        )
    return d


def load_saved_inventory(limit: int = 500) -> list[dict]:
    if SessionLocal is None:
        logger.info("Database load skipped: no database configured.")
        return []

    session = SessionLocal()
    try:
        rows = (session.query(VmInventoryRecord)
                .order_by(VmInventoryRecord.id.desc()).limit(limit).all())
        return [_row_to_dict(r) for r in rows]
    except SQLAlchemyError as exc:
        logger.exception("Failed to load saved VM inventory: %s", exc)
        return []
    finally:
        session.close()


def get_vm_created_by_date() -> dict:
    """
    Returns {date_str: count} of VMs grouped by their VMware creation date
    (the created_date field, not our discovery timestamp).
    Uses only the latest discovery snapshot per host.
    """
    if SessionLocal is None:
        return {}
    session = SessionLocal()
    try:
        import re
        from datetime import timedelta
        from collections import Counter
        from sqlalchemy import func

        subq = (
            session.query(
                VmInventoryRecord.source_host,
                func.max(VmInventoryRecord.discovered_at).label("max_dt"),
            )
            .group_by(VmInventoryRecord.source_host)
            .subquery()
        )
        # Match all rows within 30 minutes of each source's latest discovered_at.
        # New saves share one timestamp per batch, so this is exact for them;
        # legacy rows have per-VM microsecond timestamps from the same run, and
        # the window groups them as one snapshot.
        rows = (
            session.query(VmInventoryRecord.created_date)
            .join(
                subq,
                (VmInventoryRecord.source_host == subq.c.source_host)
                & (VmInventoryRecord.discovered_at >= subq.c.max_dt - timedelta(minutes=30)),
            )
            .all()
        )

        counts: Counter = Counter()
        total = 0
        with_value = 0
        not_avail  = 0
        unparsed   = 0
        sample_unparsed: list = []
        for (raw,) in rows:
            total += 1
            if not raw:
                continue
            if raw == "Not Available":
                not_avail += 1
                continue
            with_value += 1
            m = re.search(r"(\d{4}-\d{2}-\d{2})", str(raw))
            if m:
                counts[m.group(1)] += 1
            else:
                unparsed += 1
                if len(sample_unparsed) < 3:
                    sample_unparsed.append(str(raw)[:60])

        logger.info(
            "VM creation-date scan: %d rows scanned · %d with value · %d 'Not Available' · "
            "%d unparsed · %d unique dates%s",
            total, with_value, not_avail, unparsed, len(counts),
            (" · sample unparsed=" + repr(sample_unparsed)) if sample_unparsed else "",
        )
        return dict(counts)
    except SQLAlchemyError as exc:
        logger.exception("Failed to get VM creation dates: %s", exc)
        return {}
    finally:
        session.close()


def _edit_key(source_host: str, vm_name: str) -> str:
    return f"{(source_host or '').strip()}|||{(vm_name or '').strip()}".lower()


def load_asset_edits() -> dict:
    """
    Returns {edit_key: {asset_name, hostname, ip_address, os_type, os_version,
    updated_at}} for every saved edit. Empty if DB not configured.
    """
    if SessionLocal is None:
        return {}
    session = SessionLocal()
    try:
        rows = session.query(VmAssetEdit).all()
        out: dict = {}
        for r in rows:
            out[_edit_key(r.source_host, r.vm_name)] = {
                "asset_name": r.asset_name or "",
                "hostname":   r.hostname   or "",
                "ip_address": r.ip_address or "",
                "os_type":    r.os_type    or "",
                "os_version": r.os_version or "",
                "updated_at": r.updated_at.strftime("%Y-%m-%d %H:%M UTC") if r.updated_at else "",
            }
        return out
    except SQLAlchemyError as exc:
        logger.exception("Failed to load asset edits: %s", exc)
        return {}
    finally:
        session.close()


def save_asset_edit(source_host: str, vm_name: str, fields: dict) -> tuple[bool, str]:
    """
    Upsert a per-VM editable overlay. Empty strings clear the field.
    Returns (success, error_message).
    """
    if SessionLocal is None:
        return False, "Database is not configured (set DB_HOST/DB_NAME/DB_USER/DB_PASSWORD in .env)."
    if not source_host or not vm_name:
        return False, "source_host and vm_name are required."

    session = SessionLocal()
    try:
        # Defensive: make sure the vm_asset_edits table exists. This is a no-op
        # if it was already created at app startup; it covers the case where
        # the service was running before this feature was deployed.
        try:
            VmAssetEdit.__table__.create(bind=engine, checkfirst=True)
        except SQLAlchemyError:
            pass

        row = (session.query(VmAssetEdit)
               .filter(VmAssetEdit.source_host == source_host,
                       VmAssetEdit.vm_name     == vm_name)
               .one_or_none())
        if row is None:
            row = VmAssetEdit(source_host=source_host, vm_name=vm_name)
            session.add(row)
        row.asset_name = (fields.get("asset_name") or "").strip()
        row.hostname   = (fields.get("hostname")   or "").strip()
        row.ip_address = (fields.get("ip_address") or "").strip()
        row.os_type    = (fields.get("os_type")    or "").strip()
        row.os_version = (fields.get("os_version") or "").strip()
        row.updated_at = datetime.utcnow()
        session.commit()
        return True, ""
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Failed to save asset edit: %s", exc)
        # Surface the root cause to the caller — strip the SQLAlchemy URL noise
        msg = str(getattr(exc, "orig", exc)) or str(exc)
        return False, msg[:300]
    except Exception as exc:
        logger.exception("Unexpected error saving asset edit: %s", exc)
        return False, str(exc)[:300]
    finally:
        session.close()


def delete_asset_edit(source_host: str, vm_name: str) -> bool:
    if SessionLocal is None:
        return False
    session = SessionLocal()
    try:
        (session.query(VmAssetEdit)
         .filter(VmAssetEdit.source_host == source_host,
                 VmAssetEdit.vm_name     == vm_name)
         .delete())
        session.commit()
        return True
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Failed to delete asset edit: %s", exc)
        return False
    finally:
        session.close()


def load_latest_inventory_all_hosts() -> list[dict]:
    """
    Return the most-recent discovery snapshot for EVERY source host,
    with source_host and discovered_at included in each record.
    Used by the consolidated dashboard view.
    """
    if SessionLocal is None:
        logger.info("Database load skipped: no database configured.")
        return []

    session = SessionLocal()
    try:
        from datetime import timedelta
        from sqlalchemy import func
        subq = (
            session.query(
                VmInventoryRecord.source_host,
                func.max(VmInventoryRecord.discovered_at).label("max_dt"),
            )
            .group_by(VmInventoryRecord.source_host)
            .subquery()
        )
        # 30-minute window — see note in get_vm_created_by_date().
        rows = (
            session.query(VmInventoryRecord)
            .join(
                subq,
                (VmInventoryRecord.source_host == subq.c.source_host)
                & (VmInventoryRecord.discovered_at >= subq.c.max_dt - timedelta(minutes=30)),
            )
            .order_by(VmInventoryRecord.source_host, VmInventoryRecord.id)
            .all()
        )
        return [_row_to_dict(r, include_source=True) for r in rows]
    except SQLAlchemyError as exc:
        logger.exception("Failed to load consolidated inventory: %s", exc)
        return []
    finally:
        session.close()
