"""
vmware_client.py
----------------
Handles all pyVmomi connections and raw VM property retrieval.
No credential storage; connection objects are short-lived per request.
"""

import ssl
import logging
from datetime import datetime
from typing import Optional

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

logger = logging.getLogger(__name__)


class VMwareConnectionError(Exception):
    """Raised when connection to VMware host fails."""
    pass


class VMwareAuthError(Exception):
    """Raised when credentials are invalid."""
    pass


def _build_ssl_context(verify_ssl: bool) -> ssl.SSLContext:
    """Build an SSL context, optionally disabling verification."""
    if not verify_ssl:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context = ssl.create_default_context()
    return context


def connect(host: str, username: str, password: str,
            port: int = 443, verify_ssl: bool = False):
    """
    Establish a SmartConnect session to vCenter or ESXi.
    Returns a ServiceInstance. Caller must Disconnect() when done.
    """
    ssl_context = _build_ssl_context(verify_ssl)
    try:
        si = SmartConnect(
            host=host,
            user=username,
            pwd=password,
            port=port,
            sslContext=ssl_context,
        )
        return si
    except vim.fault.InvalidLogin:
        raise VMwareAuthError(f"Invalid credentials for {username}@{host}")
    except ConnectionRefusedError:
        raise VMwareConnectionError(f"Connection refused at {host}:{port}")
    except OSError as exc:
        raise VMwareConnectionError(f"Cannot reach {host}:{port} — {exc}")
    except Exception as exc:
        raise VMwareConnectionError(f"Unexpected error connecting to {host}: {exc}")


def _get_all_vms(si) -> list:
    """Walk the entire inventory tree and return all VirtualMachine objects."""
    content = si.RetrieveContent()
    container = content.viewManager.CreateContainerView(
        content.rootFolder,
        [vim.VirtualMachine],
        recursive=True,
    )
    vms = list(container.view)
    container.Destroy()
    return vms


def _safe(obj, *attrs, default="Not Available"):
    """Safely navigate a chain of attributes; return default on any failure."""
    try:
        for attr in attrs:
            if obj is None:
                return default
            obj = getattr(obj, attr, None)
        return obj if obj is not None else default
    except Exception:
        return default


def _get_created_date(vm) -> str:
    """
    Best-effort created date:
    1. config.createDate (vCenter 6.5+)
    2. Fall back to 'Not Available'
    """
    try:
        cd = _safe(vm, "config", "createDate")
        if cd and isinstance(cd, datetime):
            return cd.strftime("%Y-%m-%d %H:%M:%S UTC")
        return "Not Available"
    except Exception:
        return "Not Available"


def _get_macs_and_ips(vm) -> tuple[list[str], list[str]]:
    """Extract MAC addresses and IPs from network adapters and guest info."""
    macs = []
    ips = []

    # MACs from hardware devices
    try:
        devices = _safe(vm, "config", "hardware", "device") or []
        for dev in devices:
            if isinstance(dev, (vim.vm.device.VirtualEthernetCard,
                                vim.vm.device.VirtualVmxnet3,
                                vim.vm.device.VirtualE1000,
                                vim.vm.device.VirtualE1000e)):
                mac = getattr(dev, "macAddress", None)
                if mac:
                    macs.append(mac)
    except Exception:
        pass

    # IPs from guest info (requires VMware Tools)
    try:
        nics = _safe(vm, "guest", "net") or []
        for nic in nics:
            ip_config = getattr(nic, "ipConfig", None)
            if ip_config:
                for ip_addr in (ip_config.ipAddress or []):
                    addr = getattr(ip_addr, "ipAddress", None)
                    if addr and not addr.startswith("fe80") and addr != "127.0.0.1":
                        ips.append(addr)
    except Exception:
        pass

    # Fallback: guest.ipAddress (primary IP)
    if not ips:
        primary = _safe(vm, "guest", "ipAddress")
        if primary and primary != "Not Available":
            ips.append(primary)

    return macs or ["Not Available"], ips or ["Not Available"]


def _get_esxi_host_name(vm) -> str:
    """Return the ESXi host name for this VM."""
    try:
        runtime_host = _safe(vm, "runtime", "host")
        return _safe(runtime_host, "name")
    except Exception:
        return "Not Available"


def _get_esxi_host_ip(vm) -> str:
    """Resolve the ESXi host's management IP for this VM."""
    try:
        runtime_host = _safe(vm, "runtime", "host")
        if runtime_host is None or runtime_host == "Not Available":
            return "Not Available"
        vnics = _safe(runtime_host, "config", "network", "vnic") or []
        for vnic in vnics:
            ip = _safe(vnic, "spec", "ip", "ipAddress")
            if ip and ip != "Not Available":
                return ip
        return "Not Available"
    except Exception:
        return "Not Available"


def get_vm_inventory(si) -> list[dict]:
    """
    Collect all VM details and return as a list of dicts.
    Missing VMware Tools data is gracefully marked as 'Not Available'.
    """
    vms = _get_all_vms(si)
    inventory = []

    for vm in vms:
        try:
            # Skip templates
            if _safe(vm, "config", "template") is True:
                continue

            macs, ips = _get_macs_and_ips(vm)

            record = {
                "name":            _safe(vm, "name"),
                "hostname":        _safe(vm, "guest", "hostName"),
                "ips":             ips,
                "esxi_host_name":  _get_esxi_host_name(vm),
                "esxi_host_ip":    _get_esxi_host_ip(vm),
                "os_type":         _safe(vm, "guest", "guestFamily"),
                "os_version":      _safe(vm, "guest", "guestFullName"),
                "macs":            macs,
                "created_date":    _get_created_date(vm),
                "power_state":     _safe(vm, "runtime", "powerState", default="unknown"),
                "tools_status":    _safe(vm, "guest", "toolsRunningStatus", default="Not Available"),
            }
            inventory.append(record)
        except Exception as exc:
            logger.warning("Skipping VM due to error: %s", exc)
            continue

    return inventory


def discover(host: str, username: str, password: str,
             port: int = 443, verify_ssl: bool = False) -> list[dict]:
    """
    Full discovery pipeline: connect → collect → disconnect.
    Returns list of VM dicts. Always disconnects cleanly.
    """
    si = connect(host, username, password, port, verify_ssl)
    try:
        return get_vm_inventory(si)
    finally:
        Disconnect(si)
