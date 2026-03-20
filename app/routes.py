"""Main routes blueprint."""
from __future__ import annotations

import re
import subprocess

from flask import Blueprint, jsonify, render_template, request
from flask_login import login_required

from . import wireguard, firewall
from .peer_names import get_peer_name_store

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
    interfaces = wireguard.get_interfaces()
    if not interfaces:
        return jsonify({"ok": False, "error": "No WireGuard interfaces found."}), 400

    errors = []
    for iface in interfaces:
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", iface):
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


# ---------------------------------------------------------------------------
# Peer name aliases
# ---------------------------------------------------------------------------


@main_bp.route("/api/peer_names", methods=["GET"])
@login_required
def api_peer_names():
    """Return all peer name aliases as a mapping of public_key -> name."""
    return jsonify(get_peer_name_store().get_all())


@main_bp.route("/api/peer_names/<path:public_key>", methods=["POST"])
@login_required
def api_set_peer_name(public_key):
    """Set or update the display name for a peer."""
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    if not name:
        return jsonify({"ok": False, "error": "Name cannot be empty"}), 400
    if len(name) > 64:
        return jsonify({"ok": False, "error": "Name too long (max 64 characters)"}), 400
    get_peer_name_store().set(public_key, name)
    return jsonify({"ok": True})


@main_bp.route("/api/peer_names/<path:public_key>", methods=["DELETE"])
@login_required
def api_delete_peer_name(public_key):
    """Remove the display name for a peer (reverts to showing the public key)."""
    get_peer_name_store().delete(public_key)
    return jsonify({"ok": True})
