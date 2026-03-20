"""Main routes blueprint."""
from __future__ import annotations

import subprocess

from flask import Blueprint, jsonify, render_template
from flask_login import login_required

from . import wireguard, firewall

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")


@main_bp.route("/firewall")
@login_required
def firewall_page():
    rules = firewall.get_firewall_rules()
    return render_template("firewall.html", rules=rules)


# ---------------------------------------------------------------------------
# JSON API endpoints (polled by the dashboard JS every 5 s)
# ---------------------------------------------------------------------------


@main_bp.route("/api/status")
@login_required
def api_status():
    return jsonify(wireguard.get_wg_status())


@main_bp.route("/api/peers")
@login_required
def api_peers():
    return jsonify(wireguard.get_peers())


@main_bp.route("/api/throughput")
@login_required
def api_throughput():
    return jsonify(wireguard.get_throughput_history())


@main_bp.route("/api/ping")
@login_required
def api_ping():
    return jsonify(wireguard.get_ping_history())


@main_bp.route("/api/restart", methods=["POST"])
@login_required
def api_restart():
    """Restart the WireGuard service for each active interface."""
    import re as _re
    interfaces = wireguard.get_interfaces()
    if not interfaces:
        return jsonify({"ok": False, "error": "No WireGuard interfaces found."}), 400

    errors = []
    for iface in interfaces:
        if not _re.fullmatch(r"[a-zA-Z0-9_-]+", iface):
            errors.append(f"Invalid interface name: {iface!r}")
            continue
        try:
            result = subprocess.run(
                ["systemctl", "restart", f"wg-quick@{iface}"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                errors.append(f"{iface}: {result.stderr.strip() or 'restart failed'}")
        except FileNotFoundError:
            errors.append(f"{iface}: systemctl not found")
        except subprocess.TimeoutExpired:
            errors.append(f"{iface}: restart timed out")

    if errors:
        return jsonify({"ok": False, "error": "; ".join(errors)}), 500
    return jsonify({"ok": True, "restarted": interfaces})
