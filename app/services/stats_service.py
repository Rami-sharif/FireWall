"""
Traffic statistics: aggregate from logs and optional periodic snapshot.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from app.db.database import get_db
from app.db.models import TrafficLog


def get_stats_from_logs() -> dict[str, Any]:
    """
    Aggregate stats from traffic_logs (total, allowed, blocked, alert count, protocol breakdown).
    """
    db = get_db()
    try:
        logs = db.query(TrafficLog).all()
        total = len(logs)
        allowed = sum(1 for l in logs if l.action == "ALLOW")
        blocked = sum(1 for l in logs if l.action == "BLOCK")
        alert_count = sum(1 for l in logs if l.action == "ALERT")
        protocol_breakdown = defaultdict(int)
        for l in logs:
            p = l.protocol or "OTHER"
            protocol_breakdown[p] += 1
        return {
            "total_packets": total,
            "allowed_count": allowed,
            "blocked_count": blocked,
            "alert_count": alert_count,
            "suspicious_count": alert_count,  # alias for dashboard
            "protocol_breakdown": dict(protocol_breakdown),
        }
    finally:
        db.close()


def get_top_sources(limit: int = 10) -> list[dict[str, Any]]:
    """Top source IPs by packet count."""
    db = get_db()
    try:
        from sqlalchemy import func
        rows = (
            db.query(TrafficLog.src_ip, func.count(TrafficLog.id).label("count"))
            .filter(TrafficLog.src_ip.isnot(None))
            .group_by(TrafficLog.src_ip)
            .order_by(func.count(TrafficLog.id).desc())
            .limit(limit)
            .all()
        )
        return [{"source_ip": r.src_ip, "count": r.count} for r in rows]
    finally:
        db.close()
