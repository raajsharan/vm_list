# VMware VM Inventory Tool

A lightweight Flask web application that discovers and displays virtual machine inventory from VMware vCenter or standalone ESXi hosts.

## Features

- Connect to **vCenter** or **standalone ESXi** via pyVmomi
- Collect: VM name, guest hostname, IPs, ESXi host IP, OS type/version, MAC addresses, created date, power state
- **Capacity & snapshots**: vCPU, memory, committed/provisioned storage, datastores, snapshot count + oldest-snapshot age
- **Multi-user authentication** with `admin` / `viewer` roles, CSRF protection, and hardened session cookies
- **Change detection (Drift)**: what was added / removed / changed between the two most recent snapshots per host
- **Stale & orphaned VM hygiene**: removed-since-last-run, powered-on-but-no-IP, and powered-off lists
- **Snapshot age report**: flags snapshots older than a configurable threshold
- **In-app notifications**: discovery failures, inventory drift, and untracked VMs — surfaced as a popup on next login
- **Asset Inventory integration**: match VM IPs against the internal Asset / Ext. Asset Inventory, edit, and push entries
- **MAC → IP lookup** from uploaded spreadsheets
- Stats **dashboard**, **ESXi topology** view, **sortable/searchable** tables
- **Export** to CSV or JSON · **read-only JSON API** (`/api/v1/*`)
- **Scheduled discovery** (in-process scheduler, cron, or systemd timer)
- vCenter/ESXi credentials are encrypted at rest; passwords are never logged

---

## Requirements

- Ubuntu Server 24.04 LTS
- Python 3.12
- **PostgreSQL** — required for authentication, dashboards, drift, and notifications
- Network access to vCenter/ESXi on port 443
- VMware Tools running on VMs (for hostname/IP data)

---

## Installation

### 1. Clone / copy the project

```bash
sudo mkdir -p /opt/vmware-inventory
sudo cp -r . /opt/vmware-inventory/
cd /opt/vmware-inventory
```

### 2. Create a Python virtual environment

```bash
python3.12 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Set the Flask secret key (for session signing)

```bash
export FLASK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
```

### 4. Configure PostgreSQL (required)

Authentication, dashboards, drift, and notifications all need PostgreSQL.
Set the `DB_*` variables in `.env` (preferred) or a single `DATABASE_URL`:

```ini
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vmware_inventory
DB_USER=vmware_user
DB_PASSWORD=change-me
# Required for credential encryption:
ENCRYPTION_KEY=<output of: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
```

The app creates all required tables (and migrates new columns) automatically on
startup. To migrate an existing database out-of-band instead, run:

```bash
psql "$DATABASE_URL" -f sql/migrate_v2_auth_drift.sql
```

### 5. First login

On first startup, if no users exist, an initial admin account is created from
`INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD` (default **admin / admin**).
**Log in and change the password immediately** via the **Users** page. A warning
notification is raised until you do.

---

## Authentication & Roles

| Role     | Can do                                                                 |
|----------|------------------------------------------------------------------------|
| `admin`  | Everything: discovery, credentials, settings, asset edits, user mgmt    |
| `viewer` | Read-only: dashboards, drift, stale, snapshots, MAC lookup, exports     |

- All form submissions are CSRF-protected (token auto-injected into every POST form).
- Set `SESSION_COOKIE_SECURE=true` when serving over HTTPS.
- Admin-only mutation routes are enforced server-side, not just hidden in the UI.

---

## Read-only JSON API

Endpoints under `/api/v1/` accept either an authenticated browser session or an
`X-API-Key: <API_KEY>` header (set `API_KEY` in `.env`):

| Endpoint                  | Returns                                              |
|---------------------------|------------------------------------------------------|
| `GET /api/v1/vms`         | Consolidated VM list (optional `?host=` filter)      |
| `GET /api/v1/hosts`       | Per-host VM counts + power states                    |
| `GET /api/v1/stats`       | Totals, power states, asset-inventory coverage       |
| `GET /api/v1/drift`       | Added/removed/changed VMs per host                   |
| `GET /api/v1/notifications`| Recent notifications                                |

```bash
curl -H "X-API-Key: $API_KEY" http://localhost:8000/api/v1/stats
```

---

## Running the App

### Development mode (foreground)

```bash
cd /opt/vmware-inventory
source venv/bin/activate
python3 app.py
```

Access at: **http://localhost:5000**

### Production mode with systemd

```bash
# Install service
sudo cp vmware-inventory.service /etc/systemd/system/
# Edit the service file to set FLASK_SECRET
sudo nano /etc/systemd/system/vmware-inventory.service

sudo systemctl daemon-reload
sudo systemctl enable vmware-inventory
sudo systemctl start vmware-inventory

# Check status
sudo systemctl status vmware-inventory
sudo journalctl -u vmware-inventory -f
```

> **Multi-worker note:** the in-process scheduler must run in exactly one
> process. Under gunicorn with multiple workers, a file lock ensures only the
> first worker starts the scheduler. Prefer `--workers 1` for the scheduler
> process, or set `ENABLE_SCHEDULER=false` and run discovery via the systemd
> timer / cron below.

---

## How to Use the Web UI

1. Open **http://<server-ip>:5000** in a browser
2. Enter:
   - **Host/IP** — your vCenter or ESXi hostname/IP
   - **Username** — e.g., `administrator@vsphere.local` or `root`
   - **Password** — entered securely (never stored)
   - **Port** — default 443
   - **SSL verification** — uncheck for self-signed certs (common in labs)
3. Click **Discover VMs**
4. Results appear in a sortable, filterable table
5. Use **Export CSV** or **Export JSON** to download results
6. **Cached View** shows the last discovery without re-connecting

---

## Scheduled Discovery (Optional)

### Option A: cron

Add to crontab (`crontab -e`):

```cron
# Discover VMs every hour
0 * * * * VMWARE_HOST=192.168.1.10 VMWARE_USER=admin@vsphere.local VMWARE_PASS='secret' /opt/vmware-inventory/venv/bin/python3 /opt/vmware-inventory/discover_cron.py >> /var/log/vmware-discovery.log 2>&1
```

### Option B: systemd timer

```bash
# Create credentials file (protect it!)
sudo mkdir -p /etc/vmware-inventory
sudo tee /etc/vmware-inventory/credentials.env > /dev/null <<EOF
VMWARE_HOST=192.168.1.10
VMWARE_USER=administrator@vsphere.local
VMWARE_PASS=YourPasswordHere
EOF
sudo chmod 600 /etc/vmware-inventory/credentials.env
sudo chown www-data:www-data /etc/vmware-inventory/credentials.env

# Install units
sudo cp vmware-discovery.service vmware-discovery.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vmware-discovery.timer

# Verify
sudo systemctl list-timers vmware-discovery.timer
```

---

## Project Structure

```
vmware-inventory/
├── app.py                    # Flask app factory + routes + request guard (auth/CSRF)
├── auth.py                   # Multi-user auth, CSRF, decorators, admin bootstrap
├── notifier.py               # Generates notifications from discovery events
├── vmware_client.py          # pyVmomi connection, VM data, capacity & snapshots
├── data_processor.py         # Data normalisation for display/export
├── database.py               # SQLAlchemy: inventory, users, notifications, drift
├── credential_store.py       # Encrypted vCenter/ESXi credential storage
├── scheduler.py              # APScheduler + single-process file lock
├── asset_lookup.py           # Internal Asset Inventory API client
├── mac_lookup.py             # MAC→IP spreadsheet parsing/index
├── config_store.py           # .env-backed UI settings
├── cache.py                  # File-based result cache (DB fallback)
├── discover_cron.py          # CLI script for scheduled/cron use
├── templates/                # base, login, users, account, notifications,
│   │                         #   drift, stale, snapshots, db_required, +existing
│   └── ...
├── static/style.css          # UI styles
├── sql/
│   ├── create_vm_asset_edits.sql
│   └── migrate_v2_auth_drift.sql   # users, notifications, capacity columns
├── cache/                    # Auto-created; per-host JSON, keys, scheduler lock
├── requirements.txt
├── vmware-inventory.service  # systemd service unit
├── vmware-discovery.service  # systemd one-shot discovery unit
├── vmware-discovery.timer    # systemd timer unit
└── README.md
```

---

## VM Data Availability Notes

| Field | Availability |
|-------|-------------|
| VM Name | Always available |
| Power State | Always available |
| Guest Hostname | Requires VMware Tools running |
| IP Addresses | Requires VMware Tools running |
| MAC Addresses | Always available (from hardware config) |
| OS Type/Version | Requires VMware Tools or manual config |
| ESXi Host IP | Available if user has host read access |
| Created Date | vCenter 6.5+ only; `Not Available` on ESXi |

Missing fields are shown as **Not Available** — never as errors.

---

## Security Notes

- Passwords are **never** stored, logged, or cached
- Only VM inventory data (no credentials) is written to the cache file
- The cache file is stored at `cache/last_inventory.json` — protect it if VMs are sensitive
- Run the service as a non-root user (`www-data` recommended)
- Set `FLASK_SECRET` to a strong random value in production
- For internet-exposed deployments, place behind nginx with HTTPS

---

## Sample Output (JSON)

```json
[
  {
    "name": "web-server-01",
    "hostname": "web01.example.com",
    "ips": ["10.0.1.50", "10.0.2.50"],
    "esxi_host": "192.168.1.21",
    "os_type": "linuxGuest",
    "os_version": "Ubuntu Linux (64-bit)",
    "macs": ["00:50:56:ab:cd:ef"],
    "created_date": "2023-06-15 09:22:41 UTC",
    "power_state": "poweredOn",
    "tools_status": "guestToolsRunning"
  }
]
```
