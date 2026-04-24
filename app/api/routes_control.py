"""
Flask routes: sniffer start/stop and enforcement mode toggle.
"""

from flask import Blueprint, jsonify, request

from app.engine.enforcer import cleanup_all_blocks
from app.engine.sniffer import get_sniffer
from app.utils.config import get_config, set_enforcement

bp = Blueprint("control", __name__, url_prefix="/api/control")


@bp.route("/start", methods=["POST"])
def start():
    sniffer = get_sniffer()
    sniffer.start()
    return jsonify({"ok": True, "running": sniffer.is_running, "error": sniffer.last_error})


@bp.route("/stop", methods=["POST"])
def stop():
    sniffer = get_sniffer()
    sniffer.stop()
    return jsonify({"ok": True, "running": sniffer.is_running})


@bp.route("/status", methods=["GET"])
def status():
    sniffer = get_sniffer()
    cfg = get_config()
    return jsonify({
        "running": sniffer.is_running,
        "error": sniffer.last_error,
        "simulation_mode": cfg.get("SIMULATION_MODE", True),
        "enforcement_enabled": cfg.get("ENFORCEMENT_ENABLED", False),
    })


@bp.route("/enforcement", methods=["GET"])
def enforcement_get():
    cfg = get_config()
    return jsonify({
        "simulation_mode": cfg.get("SIMULATION_MODE", True),
        "enforcement_enabled": cfg.get("ENFORCEMENT_ENABLED", False),
    })


@bp.route("/enforcement", methods=["POST"])
def enforcement_set():
    data = request.get_json(force=True, silent=True) or {}
    simulation_mode = bool(data.get("simulation_mode", True))
    enforcement_enabled = bool(data.get("enforcement_enabled", False))
    was_enforcing = get_config().get("ENFORCEMENT_ENABLED", False)
    set_enforcement(simulation_mode, enforcement_enabled)
    cfg = get_config()
    # If enforcement was active and is now being disabled, flush all iptables rules
    if was_enforcing and not cfg.get("ENFORCEMENT_ENABLED", False):
        cleanup_all_blocks()
    return jsonify({
        "ok": True,
        "simulation_mode": cfg.get("SIMULATION_MODE", True),
        "enforcement_enabled": cfg.get("ENFORCEMENT_ENABLED", False),
    })
