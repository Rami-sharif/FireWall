"""
Flask routes: alerts.
"""

from flask import Blueprint, request, jsonify

from app.services.alert_service import get_alerts, get_alerts_count

bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")


@bp.route("", methods=["GET"])
def list_alerts():
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))
    severity = request.args.get("severity") or None
    alerts = get_alerts(limit=limit, offset=offset, severity=severity)
    total = get_alerts_count(severity=severity)
    return jsonify({
        "items": [a.to_dict() for a in alerts],
        "total": total,
        "limit": limit,
        "offset": offset,
    })
