# wireguard-monitor-copilot

A Flask-based web application running on Linux (port 5000) that provides a real-time monitoring UI for WireGuard VPN.

## Features

- **WireGuard status** – interface name, public key, listening port
- **Peer status table** – shows each peer's endpoint, allowed IPs, last handshake and connected/disconnected state
- **Throughput graphs** – per-peer RX/TX bytes-per-second chart, refreshed every 5 seconds
- **Ping latency graphs** – per-peer round-trip time chart, refreshed every 5 seconds
- **Firewall rules page** – displays both `iptables` and `nftables` rulesets
- **User authentication** – login/logout with configurable credentials (via environment variables)

## Requirements

- Python 3.10+
- Linux with WireGuard tools (`wg`) installed (the UI gracefully degrades when `wg` is absent)

## Quick Start

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. (Optional) set credentials via environment variables
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=changeme   # change this!
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# 3. Run the application
python run.py
```

Then open **http://\<your-server\>:5000** in a browser and log in.

## Configuration

| Environment variable | Default      | Description                                      |
|----------------------|--------------|--------------------------------------------------|
| `ADMIN_USERNAME`     | `admin`      | Login username                                   |
| `ADMIN_PASSWORD`     | `changeme`   | Login password – **change in production!**       |
| `SECRET_KEY`         | random       | Flask secret key for session signing             |
| `WG_INTERFACE`       | (auto)       | Force a specific WireGuard interface name        |
| `MAX_HISTORY`        | `60`         | Number of 5-second data points kept per peer     |

## Project Structure

```
├── run.py              # Entry point
├── config.py           # Configuration class
├── requirements.txt    # Python dependencies
├── tests.py            # Unit tests
└── app/
    ├── __init__.py     # Flask application factory
    ├── auth.py         # Login / logout blueprint
    ├── routes.py       # Dashboard + API blueprints
    ├── wireguard.py    # WireGuard data collection & history
    ├── firewall.py     # iptables / nftables reader
    ├── templates/
    │   ├── base.html
    │   ├── login.html
    │   ├── dashboard.html
    │   └── firewall.html
    └── static/
        ├── css/style.css
        ├── js/dashboard.js
        └── vendor/        # Bootstrap 5, Bootstrap Icons, Chart.js (local)
```

## Running Tests

```bash
pip install pytest
python -m pytest tests.py -v
```
