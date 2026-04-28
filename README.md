# VMware VM Inventory Tool

A lightweight Flask web application that discovers and displays virtual machine inventory from VMware vCenter or standalone ESXi hosts.

## Features

- Connect to **vCenter** or **standalone ESXi** via pyVmomi
- Collect: VM name, guest hostname, IPs, ESXi host IP, OS type/version, MAC addresses, created date, power state
- **Sortable, searchable** results table
- **Export** to CSV or JSON
- **Cached results** — last discovery is persisted for offline viewing
- **Scheduled discovery** via cron or systemd timer
- No credentials are ever stored or logged

---

## Requirements

- Ubuntu Server 24.04 LTS
- Python 3.12
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

### 4. Configure PostgreSQL persistence

If you want discoveries saved to PostgreSQL, set `DATABASE_URL` before starting the app:

```bash
export DATABASE_URL=postgresql+psycopg2://user:password@localhost/vm_inventory
```

The app will create the required table automatically on startup.

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
├── app.py                    # Flask app + routes
├── vmware_client.py          # pyVmomi connection & VM data retrieval
├── data_processor.py         # Data normalisation for display/export
├── cache.py                  # File-based result cache
├── discover_cron.py          # CLI script for scheduled/cron use
├── templates/
│   ├── base.html             # Base layout
│   ├── index.html            # Connection form
│   └── inventory.html        # VM results table
├── static/
│   └── style.css             # UI styles
├── cache/                    # Auto-created; stores last_inventory.json
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
