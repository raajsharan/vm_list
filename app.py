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

from dotenv import load_dotenv
load_dotenv()

import vmware_client
import data_processor
import cache as cache_store
import database
import credential_store
import scheduler
import config_store
import mac_lookup as mac_lookup_store

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
    scheduler.init()

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
        available_hosts = cache_store.list_hosts()
        selected_host   = request.args.get("host", "").strip()

        if selected_host:
            payload = cache_store.load_host(selected_host)
            if not payload:
                flash(f"No cached results found for {selected_host}.", "warning")
                return redirect(url_for("view_cached"))
        else:
            payload = cache_store.load()
            if not payload and available_hosts:
                return redirect(url_for("view_cached", host=available_hosts[0]))
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
            available_hosts=available_hosts,
            selected_host=payload.get("host", ""),
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

    # -----------------------------------------------------------------------
    # Credentials & Scheduler routes
    # -----------------------------------------------------------------------

    @app.route("/credentials", methods=["GET"])
    def credentials():
        creds        = credential_store.load_all()
        running      = scheduler.active_hosts()
        next_runs    = {c["host"]: scheduler.format_next_run(c["host"]) for c in creds}
        return render_template(
            "credentials.html",
            credentials=creds,
            running_hosts=running,
            scheduler_jobs=next_runs,
        )

    @app.route("/credentials/add", methods=["POST"])
    def cred_add():
        host     = request.form.get("host", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        port     = int(request.form.get("port", 443) or 443)
        verify   = request.form.get("verify_ssl") == "on"
        interval = max(5, int(request.form.get("interval_minutes", 60) or 60))

        if not host or not username or not password:
            flash("Host, username, and password are required.", "error")
            return redirect(url_for("credentials"))

        credential_store.save(host, username, password, port, verify, interval)
        scheduler.upsert(host, interval, enabled=True)
        flash(f"Credentials saved for {host}. Discovery scheduled every {interval} minutes.", "success")
        return redirect(url_for("credentials"))

    @app.route("/credentials/<path:host>/edit", methods=["POST"])
    def cred_edit(host):
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        port     = int(request.form.get("port", 443) or 443)
        verify   = request.form.get("verify_ssl") == "on"
        interval = max(5, int(request.form.get("interval_minutes", 60) or 60))

        if not username:
            flash("Username is required.", "error")
            return redirect(url_for("credentials"))

        if not password:
            existing = credential_store.load(host)
            if not existing:
                flash(f"Host {host} not found.", "error")
                return redirect(url_for("credentials"))
            password = existing["password"]

        credential_store.save(host, username, password, port, verify, interval)
        enabled = credential_store.load(host).get("enabled", True)
        scheduler.upsert(host, interval, enabled=enabled)
        flash(f"Credentials updated for {host}.", "success")
        return redirect(url_for("credentials"))

    @app.route("/credentials/<path:host>/delete", methods=["POST"])
    def cred_delete(host):
        credential_store.delete(host)
        scheduler.remove(host)
        flash(f"Credentials for {host} deleted.", "info")
        return redirect(url_for("credentials"))

    @app.route("/credentials/<path:host>/toggle", methods=["POST"])
    def cred_toggle(host):
        enabled = credential_store.toggle(host)
        cred    = credential_store.load_all()
        entry   = next((c for c in cred if c["host"] == host), {})
        interval = entry.get("interval_minutes", 60)
        scheduler.upsert(host, interval, enabled=enabled)
        state = "enabled" if enabled else "disabled"
        flash(f"Discovery for {host} {state}.", "info")
        return redirect(url_for("credentials"))

    @app.route("/credentials/<path:host>/run", methods=["POST"])
    def cred_run(host):
        if host in scheduler.active_hosts():
            flash(f"Discovery for {host} is already running.", "warning")
            return redirect(url_for("credentials"))
        scheduler.run_now(host)
        flash(f"Discovery triggered for {host}. Results will appear when complete.", "success")
        return redirect(url_for("credentials"))

    # -----------------------------------------------------------------------
    # Dashboard — consolidated multi-host view
    # -----------------------------------------------------------------------

    @app.route("/dashboard", methods=["GET"])
    def dashboard():
        creds     = credential_store.load_all()
        running   = scheduler.active_hosts()
        next_runs = {c["host"]: scheduler.format_next_run(c["host"]) for c in creds}

        raw_vms = database.load_latest_inventory_all_hosts()
        if not raw_vms:
            raw_vms = cache_store.load_all_hosts()
        vms     = data_processor.normalise_for_display(raw_vms)

        # Per-host summary derived from the consolidated records
        host_stats: dict = {}
        for vm in raw_vms:
            h = vm["source_host"]
            if h not in host_stats:
                host_stats[h] = {"count": 0, "discovered_at": vm.get("discovered_at", "")}
            host_stats[h]["count"] += 1

        distinct_hosts = sorted(host_stats.keys())

        return render_template(
            "dashboard.html",
            credentials=creds,
            running_hosts=running,
            scheduler_jobs=next_runs,
            vms=vms,
            host_stats=host_stats,
            distinct_hosts=distinct_hosts,
            total_vms=len(vms),
        )

    @app.route("/export/all/csv", methods=["GET"])
    def export_all_csv():
        raw = database.load_latest_inventory_all_hosts()
        if not raw:
            flash("No consolidated data to export. Run discovery on at least one host.", "warning")
            return redirect(url_for("dashboard"))
        rows = data_processor.to_csv_rows_consolidated(raw)
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=vm_inventory_all.csv"},
        )

    @app.route("/export/all/json", methods=["GET"])
    def export_all_json():
        raw = database.load_latest_inventory_all_hosts()
        if not raw:
            flash("No consolidated data to export.", "warning")
            return redirect(url_for("dashboard"))
        return Response(
            json.dumps(raw, indent=2, default=str),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=vm_inventory_all.json"},
        )

    # -----------------------------------------------------------------------
    # Settings routes
    # -----------------------------------------------------------------------

    @app.route("/settings", methods=["GET"])
    def settings():
        cfg      = config_store.load()
        running  = int(os.environ.get("PORT", 5000))
        mac_meta = mac_lookup_store.load_meta()
        return render_template("settings.html", cfg=cfg, running_port=running,
                               env_file=config_store.env_file_path(),
                               mac_meta=mac_meta)

    @app.route("/settings/save", methods=["POST"])
    def settings_save():
        port_raw  = request.form.get("port", "").strip()
        debug_raw = request.form.get("flask_debug") == "on"

        # Validate port
        try:
            port_int = int(port_raw)
            if not (1 <= port_int <= 65535):
                raise ValueError
        except ValueError:
            flash("Port must be an integer between 1 and 65535.", "error")
            return redirect(url_for("settings"))

        updates = {
            "PORT":        str(port_int),
            "FLASK_DEBUG": "true" if debug_raw else "false",
        }
        if config_store.save(updates):
            running = int(os.environ.get("PORT", 5000))
            if port_int != running:
                flash(
                    f"Port changed to {port_int}. "
                    "Restart the service to apply: "
                    "sudo systemctl restart vmware-inventory",
                    "warning",
                )
            else:
                flash("Settings saved.", "success")
        else:
            flash("Failed to write settings — check file permissions on .env.", "error")

        return redirect(url_for("settings"))

    @app.route("/export/mac-lookup/csv", methods=["GET"])
    def export_mac_csv():
        mapping = mac_lookup_store.load_mapping()
        index   = mac_lookup_store.build_index(mapping)

        raw_vms = database.load_latest_inventory_all_hosts()
        if not raw_vms:
            raw_vms = cache_store.load_all_hosts()

        if not raw_vms:
            flash("No VM data to export.", "warning")
            return redirect(url_for("mac_lookup"))

        rows = []
        for vm in raw_vms:
            macs = vm.get("macs", [])
            if isinstance(macs, str):
                macs = [m.strip() for m in macs.split("|") if m.strip()]

            all_matches = []
            for mac in macs:
                norm = mac_lookup_store.normalize_mac(mac)
                if norm and norm in index:
                    all_matches.append((mac, index[norm]))

            display = data_processor.normalise_for_display([vm])[0]
            rows.append({
                "VM Name":        display["name"],
                "Hostname":       display["hostname"],
                "ESXi Host":      display["esxi_host_name"],
                "ESXi Host IP":   display["esxi_host_ip"],
                "OS Type":        display["os_type"],
                "OS Version":     display["os_version"],
                "VM IPs":         display["ip_addresses"],
                "MAC Addresses":  display["mac_addresses"],
                "Matched MACs":   " | ".join(m for m, _ in all_matches),
                "Mapped IPs":     " | ".join(r["ip_address"]     for _, r in all_matches if r["ip_address"]),
                "VLAN Group":     " | ".join(dict.fromkeys(r["vlan_group"]     for _, r in all_matches if r["vlan_group"])),
                "Data Retrieved": " | ".join(dict.fromkeys(r["data_retrieved"] for _, r in all_matches if r["data_retrieved"])),
                "Power State":    display["power_state"],
                "Source Host":    display.get("source_host", ""),
            })

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=mac_lookup.csv"},
        )

    @app.route("/settings/upload-mac", methods=["POST"])
    def upload_mac_file():
        f = request.files.get("mac_file")
        if not f or not f.filename:
            flash("No file selected.", "error")
            return redirect(url_for("settings"))

        ext = os.path.splitext(f.filename)[1].lower()
        if ext not in (".xlsx", ".xls", ".csv"):
            flash("Unsupported file type. Please upload a .xlsx or .csv file.", "error")
            return redirect(url_for("settings"))

        try:
            rows, meta = mac_lookup_store.parse_file(f)
            if not rows:
                flash("File parsed but no valid MAC address rows were found. "
                      "Check that the file has 'MAC Address' and 'IP Address' columns.", "warning")
                return redirect(url_for("settings"))
            mac_lookup_store.save_mapping(rows, meta)
            flash(
                f"MAC mapping loaded: {len(rows)} entries from \"{meta['filename']}\". "
                f"Columns detected — MAC: {meta['cols_detected']['mac']}, "
                f"IP: {meta['cols_detected']['ip']}.",
                "success",
            )
        except Exception as exc:
            logger.exception("MAC file parse error")
            flash(f"Failed to parse file: {exc}", "error")

        return redirect(url_for("settings"))

    @app.route("/settings/clear-mac", methods=["POST"])
    def clear_mac_file():
        mac_lookup_store.clear_mapping()
        flash("MAC address mapping cleared.", "info")
        return redirect(url_for("settings"))

    # -----------------------------------------------------------------------
    # MAC Address Lookup — compare VM MACs against uploaded IP mapping
    # -----------------------------------------------------------------------

    @app.route("/mac-lookup", methods=["GET"])
    def mac_lookup():
        mapping = mac_lookup_store.load_mapping()
        meta    = mac_lookup_store.load_meta()
        index   = mac_lookup_store.build_index(mapping)

        raw_vms = database.load_latest_inventory_all_hosts()
        if not raw_vms:
            raw_vms = cache_store.load_all_hosts()

        results = []
        for vm in raw_vms:
            macs = vm.get("macs", [])
            if isinstance(macs, str):
                macs = [m.strip() for m in macs.split("|") if m.strip()]

            all_matches = []
            for mac in macs:
                norm = mac_lookup_store.normalize_mac(mac)
                if norm and norm in index:
                    all_matches.append((mac, index[norm]))

            display = data_processor.normalise_for_display([vm])[0]
            # pipe-separated, no spaces around pipe — used for set-membership check in template
            display["matched_macs_pipe"] = "|".join(m for m, _ in all_matches)
            display["mapped_ips"]        = " | ".join(r["ip_address"]     for _, r in all_matches if r["ip_address"])
            display["vlan_groups"]       = " | ".join(dict.fromkeys(r["vlan_group"]     for _, r in all_matches if r["vlan_group"]))
            display["data_retrieved"]    = " | ".join(dict.fromkeys(r["data_retrieved"] for _, r in all_matches if r["data_retrieved"]))
            display["is_matched"]        = bool(all_matches)
            results.append(display)

        matched_count   = sum(1 for r in results if r["is_matched"])
        unmatched_count = len(results) - matched_count

        return render_template(
            "mac_lookup.html",
            results=results,
            meta=meta,
            total=len(results),
            matched=matched_count,
            unmatched=unmatched_count,
            has_mapping=bool(mapping),
        )

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
app = create_app()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="VMware Inventory Tool")
    parser.add_argument("--port", type=int, default=None,
                        help="Port to listen on (overrides PORT env var, default 5000)")
    parser.add_argument("--host", dest="bind_host", default="0.0.0.0",
                        help="Bind address (default 0.0.0.0)")
    parser.add_argument("--debug", action="store_true", default=None,
                        help="Enable debug mode (overrides FLASK_DEBUG env var)")
    args = parser.parse_args()

    port  = args.port  or int(os.environ.get("PORT", 5000))
    debug = args.debug if args.debug is not None \
            else os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    logger.info("Starting VMware Inventory app on %s:%d (debug=%s)", args.bind_host, port, debug)
    app.run(host=args.bind_host, port=port, debug=debug)
