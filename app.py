"""
app.py
------
Flask application factory + route definitions.
Credentials are NEVER stored, logged, or cached.
"""

import csv
import io
import json
import logging
import os

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, Response, session,
)

import vmware_client
import data_processor
import cache as cache_store
import database

# ---------------------------------------------------------------------------
# Logging — never log passwords
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = os.environ.get("FLASK_SECRET", os.urandom(32))
    # Sessions are server-side only; we never persist credentials there either
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    database.init_app(os.environ.get("DATABASE_URL"))

    # -----------------------------------------------------------------------
    # Routes
    # -----------------------------------------------------------------------

    @app.route("/", methods=["GET"])
    def index():
        cached = cache_store.load()
        return render_template("index.html", cached=cached)

    @app.route("/discover", methods=["POST"])
    def discover():
        host     = request.form.get("host", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")          # never log this
        port     = int(request.form.get("port", 443) or 443)
        verify   = request.form.get("verify_ssl") == "on"

        if not host or not username or not password:
            flash("Host, username, and password are all required.", "error")
            return redirect(url_for("index"))

        logger.info("Discovery requested for host=%s user=%s port=%d verify_ssl=%s",
                    host, username, port, verify)

        try:
            raw_records = vmware_client.discover(
                host=host,
                username=username,
                password=password,
                port=port,
                verify_ssl=verify,
            )
        except vmware_client.VMwareAuthError as exc:
            logger.warning("Auth failure for %s@%s", username, host)
            flash(f"Authentication failed: {exc}", "error")
            return redirect(url_for("index"))
        except vmware_client.VMwareConnectionError as exc:
            logger.warning("Connection failure to %s: %s", host, exc)
            flash(f"Connection error: {exc}", "error")
            return redirect(url_for("index"))
        except Exception as exc:
            logger.exception("Unexpected error during discovery")
            flash(f"Unexpected error: {exc}", "error")
            return redirect(url_for("index"))

        # Cache raw records (no creds)
        cache_store.save(raw_records, host)
        database.save_inventory(raw_records, host)

        display_records = data_processor.normalise_for_display(raw_records)
        flash(f"Discovery complete — {len(display_records)} VMs found on {host}.", "success")
        return render_template(
            "inventory.html",
            vms=display_records,
            host=host,
            count=len(display_records),
        )

    @app.route("/cached", methods=["GET"])
    def view_cached():
        payload = cache_store.load()
        if not payload:
            flash("No cached results found. Run a discovery first.", "warning")
            return redirect(url_for("index"))
        display_records = data_processor.normalise_for_display(payload["records"])
        return render_template(
            "inventory.html",
            vms=display_records,
            host=payload.get("host", "cached"),
            count=len(display_records),
            cached_at=payload.get("timestamp"),
        )

    @app.route("/saved", methods=["GET"])
    def view_saved():
        records = database.load_saved_inventory()
        if not records:
            flash("No saved PostgreSQL records found. Run a discovery first.", "warning")
            return redirect(url_for("index"))

        display_records = data_processor.normalise_for_display(records)
        return render_template(
            "inventory.html",
            vms=display_records,
            host="Saved Records",
            count=len(display_records),
            saved=True,
        )

    @app.route("/export/csv", methods=["GET"])
    def export_csv():
        payload = cache_store.load()
        if not payload:
            flash("No data to export. Run a discovery first.", "warning")
            return redirect(url_for("index"))

        rows = data_processor.to_csv_rows(payload["records"])
        if not rows:
            flash("No VM records to export.", "warning")
            return redirect(url_for("index"))

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=vm_inventory.csv"},
        )

    @app.route("/export/json", methods=["GET"])
    def export_json():
        payload = cache_store.load()
        if not payload:
            flash("No data to export. Run a discovery first.", "warning")
            return redirect(url_for("index"))

        return Response(
            json.dumps(payload["records"], indent=2, default=str),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=vm_inventory.json"},
        )

    @app.route("/cache/clear", methods=["POST"])
    def clear_cache():
        cache_store.clear()
        flash("Cache cleared.", "info")
        return redirect(url_for("index"))

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info("Starting VMware Inventory app on port %d (debug=%s)", port, debug)
    app.run(host="0.0.0.0", port=port, debug=debug)
