"""
database.py
-----------
Simple SQLAlchemy support for persisting discovered VM records.
Uses DATABASE_URL from the environment to connect to PostgreSQL.
"""

import json
import logging
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


def init_app(database_url: Optional[str]):
    global engine, SessionLocal
    if not database_url:
        logger.info("DATABASE_URL not set; persistence disabled.")
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
    try:
        for record in records:
            vm = VmInventoryRecord(
                discovered_at=datetime.utcnow(),
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
        rows = (
            session.query(VmInventoryRecord.created_date)
            .join(
                subq,
                (VmInventoryRecord.source_host == subq.c.source_host)
                & (VmInventoryRecord.discovered_at == subq.c.max_dt),
            )
            .all()
        )

        counts: Counter = Counter()
        for (raw,) in rows:
            if not raw or raw == "Not Available":
                continue
            m = re.search(r"(\d{4}-\d{2}-\d{2})", str(raw))
            if m:
                counts[m.group(1)] += 1

        return dict(counts)
    except SQLAlchemyError as exc:
        logger.exception("Failed to get VM creation dates: %s", exc)
        return {}
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
        from sqlalchemy import func
        subq = (
            session.query(
                VmInventoryRecord.source_host,
                func.max(VmInventoryRecord.discovered_at).label("max_dt"),
            )
            .group_by(VmInventoryRecord.source_host)
            .subquery()
        )
        rows = (
            session.query(VmInventoryRecord)
            .join(
                subq,
                (VmInventoryRecord.source_host == subq.c.source_host)
                & (VmInventoryRecord.discovered_at == subq.c.max_dt),
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
