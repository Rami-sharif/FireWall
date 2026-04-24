"""
Data management API: delete logs/alerts by various filters, data-usage stats.
"""

from flask import Blueprint, jsonify, request

from app.services.cleanup_service import (
    delete_all_logs,
    delete_logs_before,
    delete_logs_by_ip,
    delete_logs_by_action,
    delete_logs_by_protocol,
    delete_logs_by_dst_ip,
    delete_logs_date_range,
    delete_logs_older_than_days,
    delete_all_alerts,
    delete_alerts_before,
    delete_alerts_by_severity,
    delete_alerts_older_than_days,
    get_data_usage,
)

bp = Blueprint("data_management", __name__, url_prefix="/api")


# ── Log deletions ─────────────────────────────────────────────────────────────

@bp.route("/logs/clear", methods=["DELETE"])
def clear_logs():
    return jsonify(delete_all_logs())


@bp.route("/logs/before/<date>", methods=["DELETE"])
def logs_before(date):
    try:
        return jsonify(delete_logs_before(date))
    except ValueError as e:
        return jsonify({"error": str(e)}), 422


@bp.route("/logs/by-ip/<path:ip>", methods=["DELETE"])
def logs_by_ip(ip):
    return jsonify(delete_logs_by_ip(ip))


@bp.route("/logs/by-action/<action>", methods=["DELETE"])
def logs_by_action(action):
    from app.utils.constants import ACTIONS
    if action.upper() not in ACTIONS:
        return jsonify({"error": f"Unknown action. Must be one of {ACTIONS}"}), 422
    return jsonify(delete_logs_by_action(action))


@bp.route("/logs/by-protocol/<protocol>", methods=["DELETE"])
def logs_by_protocol(protocol):
    return jsonify(delete_logs_by_protocol(protocol))


@bp.route("/logs/by-dst-ip/<path:ip>", methods=["DELETE"])
def logs_by_dst_ip(ip):
    return jsonify(delete_logs_by_dst_ip(ip))


@bp.route("/logs/date-range", methods=["DELETE"])
def logs_date_range():
    start = request.args.get("start") or (request.get_json(silent=True) or {}).get("start")
    end = request.args.get("end") or (request.get_json(silent=True) or {}).get("end")
    if not start or not end:
        return jsonify({"error": "start and end query params required (YYYY-MM-DD)"}), 422
    try:
        return jsonify(delete_logs_date_range(start, end))
    except ValueError as e:
        return jsonify({"error": str(e)}), 422


@bp.route("/logs/older-than/<int:days>", methods=["DELETE"])
def logs_older_than(days):
    if days < 1:
        return jsonify({"error": "days must be >= 1"}), 422
    return jsonify(delete_logs_older_than_days(days))


# ── Alert deletions ───────────────────────────────────────────────────────────

@bp.route("/alerts/clear", methods=["DELETE"])
def clear_alerts():
    return jsonify(delete_all_alerts())


@bp.route("/alerts/before/<date>", methods=["DELETE"])
def alerts_before(date):
    try:
        return jsonify(delete_alerts_before(date))
    except ValueError as e:
        return jsonify({"error": str(e)}), 422


@bp.route("/alerts/by-severity/<severity>", methods=["DELETE"])
def alerts_by_severity(severity):
    from app.utils.constants import SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL
    valid = {SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL}
    if severity.lower() not in valid:
        return jsonify({"error": f"Unknown severity. Must be one of {sorted(valid)}"}), 422
    return jsonify(delete_alerts_by_severity(severity))


@bp.route("/alerts/older-than/<int:days>", methods=["DELETE"])
def alerts_older_than(days):
    if days < 1:
        return jsonify({"error": "days must be >= 1"}), 422
    return jsonify(delete_alerts_older_than_days(days))


# ── System / data usage ───────────────────────────────────────────────────────

@bp.route("/system/data-usage", methods=["GET"])
def data_usage():
    return jsonify(get_data_usage())
