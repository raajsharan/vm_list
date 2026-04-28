#!/usr/bin/env python3
"""
discover_cron.py
----------------
Standalone script for scheduled/cron-based VM discovery.
Credentials are read from environment variables to avoid shell history exposure.
Results are saved to the shared cache used by the web UI.

Usage (environment variables — recommended):
    export VMWARE_HOST=192.168.1.10
    export VMWARE_USER=administrator@vsphere.local
    export VMWARE_PASS=MySecret
    python3 discover_cron.py

Usage (CLI arguments):
    python3 discover_cron.py --host 192.168.1.10 --username admin@vsphere.local

The password is read ONLY from the VMWARE_PASS environment variable for safety.

Cron example (every hour):
    0 * * * * VMWARE_HOST=... VMWARE_USER=... VMWARE_PASS=... /usr/bin/python3 /opt/vmware-inventory/discover_cron.py

Systemd timer: see README.md
"""

import argparse
import logging
import os
import sys

import vmware_client
import cache as cache_store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="VMware VM inventory discovery (cron mode)")
    parser.add_argument("--host",     default=os.environ.get("VMWARE_HOST", ""),
                        help="vCenter or ESXi hostname/IP (or set VMWARE_HOST)")
    parser.add_argument("--username", default=os.environ.get("VMWARE_USER", ""),
                        help="VMware username (or set VMWARE_USER)")
    parser.add_argument("--port",     type=int, default=int(os.environ.get("VMWARE_PORT", 443)),
                        help="API port (default 443)")
    parser.add_argument("--verify-ssl", action="store_true",
                        help="Enable SSL certificate verification")
    args = parser.parse_args()

    password = os.environ.get("VMWARE_PASS", "")

    if not args.host or not args.username or not password:
        logger.error(
            "Missing credentials. Set VMWARE_HOST, VMWARE_USER, and VMWARE_PASS "
            "environment variables (or use --host / --username for host and user)."
        )
        sys.exit(1)

    logger.info("Starting scheduled discovery: host=%s user=%s port=%d",
                args.host, args.username, args.port)

    try:
        records = vmware_client.discover(
            host=args.host,
            username=args.username,
            password=password,
            port=args.port,
            verify_ssl=args.verify_ssl,
        )
    except vmware_client.VMwareAuthError as exc:
        logger.error("Authentication failed: %s", exc)
        sys.exit(2)
    except vmware_client.VMwareConnectionError as exc:
        logger.error("Connection error: %s", exc)
        sys.exit(3)
    except Exception as exc:
        logger.exception("Unexpected error: %s", exc)
        sys.exit(4)

    cache_store.save(records, args.host)
    logger.info("Discovery complete — %d VMs cached for host %s", len(records), args.host)


if __name__ == "__main__":
    main()
