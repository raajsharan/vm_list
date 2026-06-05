"""
auth.py
-------
Multi-user authentication, CSRF protection, and access-control helpers.

Users are stored in PostgreSQL (see database.User) with werkzeug-hashed
passwords. Sessions are signed by Flask's secret key. Two roles:

  * admin  — full access incl. user management, settings, asset writes
  * viewer — read-only access to inventory/dashboards/exports

A bootstrap admin is created on first startup when the users table is empty
(credentials from INITIAL_ADMIN_USERNAME / INITIAL_ADMIN_PASSWORD, defaulting
to admin / admin — a warning is logged and a notification raised until changed).
"""

import functools
import logging
import os
import secrets

from flask import (
    session, request, redirect, url_for, flash, jsonify, g,
)
from werkzeug.security import generate_password_hash, check_password_hash

import database

logger = logging.getLogger(__name__)

# Endpoints reachable without a login session.
_PUBLIC_ENDPOINTS = {"login", "static", "healthz"}


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return check_password_hash(password_hash, password)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def login_session(user: dict) -> None:
    session.clear()
    session["uid"]      = user["id"]
    session["username"] = user["username"]
    session["role"]     = user.get("role", "viewer")
    session.permanent   = True
    # Fresh CSRF token per session
    session["_csrf"] = secrets.token_urlsafe(32)


def logout_session() -> None:
    session.clear()


def is_authenticated() -> bool:
    return bool(session.get("uid"))


def current_user() -> dict:
    return {
        "id":       session.get("uid"),
        "username": session.get("username", ""),
        "role":     session.get("role", ""),
        "is_admin": session.get("role") == "admin",
    }


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

def get_csrf_token() -> str:
    tok = session.get("_csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["_csrf"] = tok
    return tok


def validate_csrf() -> bool:
    sent = (request.form.get("_csrf_token")
            or request.headers.get("X-CSRF-Token", ""))
    expected = session.get("_csrf", "")
    return bool(expected) and secrets.compare_digest(sent, expected)


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not is_authenticated():
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not is_authenticated():
            return redirect(url_for("login", next=request.path))
        if session.get("role") != "admin":
            flash("That action requires an administrator account.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# API-key auth (read-only JSON API)
# ---------------------------------------------------------------------------

def api_key_valid() -> bool:
    """An active session OR a matching X-API-Key header grants API access."""
    if is_authenticated():
        return True
    configured = os.environ.get("API_KEY", "")
    sent = request.headers.get("X-API-Key", "")
    return bool(configured) and secrets.compare_digest(sent, configured)


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def bootstrap_admin() -> None:
    """Create an initial admin account if the users table is empty."""
    if not database.is_configured():
        logger.warning("Database not configured — authentication is unavailable.")
        return
    try:
        if database.count_users() > 0:
            return
    except Exception as exc:
        logger.warning("Could not check users table: %s", exc)
        return

    username = os.environ.get("INITIAL_ADMIN_USERNAME", "admin").strip() or "admin"
    password = os.environ.get("INITIAL_ADMIN_PASSWORD", "admin")
    ok, err = database.create_user(username, hash_password(password),
                                   role="admin", active=True)
    if ok:
        logger.warning(
            "Bootstrapped initial admin user '%s'. CHANGE THIS PASSWORD IMMEDIATELY "
            "via the Users page.", username,
        )
        database.add_notification(
            "warning", "system",
            f"Initial admin account '{username}' created with a default password. "
            "Change it now in Users.",
        )
    else:
        logger.error("Failed to bootstrap admin user: %s", err)
