"""
Flask routes: traffic logs.
"""

from flask import Blueprint, request, jsonify

from app.services.log_service import get_logs, get_logs_count

bp = Blueprint("logs", __name__, url_prefix="/api/logs")


@bp.route("", methods=["GET"])
def list_logs():
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))
    src_ip = request.args.get("src_ip") or None
    action = request.args.get("action") or None
    logs = get_logs(limit=limit, offset=offset, src_ip=src_ip, action=action)
    total = get_logs_count(src_ip=src_ip, action=action)
    return jsonify({
        "items": [l.to_dict() for l in logs],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


@bp.route("/blocked", methods=["GET"])
def list_blocked_logs():
    """Return BLOCK/ALERT logs enriched with rule name, matched pattern, and severity."""
    from sqlalchemy import or_
    from app.db.database import get_db
    from app.db.models import TrafficLog, Rule

    limit = min(int(request.args.get("limit", 50)), 500)
    offset = int(request.args.get("offset", 0))
    src_ip = request.args.get("src_ip") or None
    protocol = request.args.get("protocol") or None
    from_time = request.args.get("from_time") or None
    to_time = request.args.get("to_time") or None

    db = get_db()
    try:
        q = db.query(TrafficLog).filter(
            or_(TrafficLog.action == "BLOCK", TrafficLog.action == "ALERT")
        ).order_by(TrafficLog.id.desc())
        if src_ip:
            q = q.filter(TrafficLog.src_ip == src_ip)
        if protocol:
            q = q.filter(TrafficLog.protocol == protocol.upper())
        if from_time:
            from datetime import datetime
            try:
                q = q.filter(TrafficLog.timestamp >= datetime.fromisoformat(from_time))
            except ValueError:
                pass
        if to_time:
            from datetime import datetime
            try:
                q = q.filter(TrafficLog.timestamp <= datetime.fromisoformat(to_time))
            except ValueError:
                pass

        total = q.count()
        logs = q.offset(offset).limit(limit).all()

        # Batch-load rules for name and payload_pattern enrichment
        rule_ids = {l.rule_id for l in logs if l.rule_id is not None}
        rule_map = {}
        if rule_ids:
            rules = db.query(Rule).filter(Rule.id.in_(rule_ids)).all()
            rule_map = {r.id: r for r in rules}

        # Detection-type keywords to derive a human-readable attack_type label
        _tag_labels = {
            "syn_flood": "SYN Flood",
            "icmp_flood": "ICMP Flood",
            "port_scan": "Port Scan",
            "rate_limit": "Rate Limit",
            "suspicious_payload": "Malicious Payload",
        }

        items = []
        for l in logs:
            d = l.to_dict()
            rule = rule_map.get(l.rule_id)
            d["rule_name"] = rule.name if rule else None
            d["matched_pattern"] = rule.payload_pattern if rule else None
            d["severity"] = "high" if l.action == "BLOCK" else "medium"
            reason_lower = (l.reason or "").lower()
            attack_type = None
            for tag, label in _tag_labels.items():
                if tag in reason_lower:
                    attack_type = label
                    break
            d["attack_type"] = attack_type
            items.append(d)

        return jsonify({"items": items, "total": total, "limit": limit, "offset": offset})
    finally:
        db.close()
