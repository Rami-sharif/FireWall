"""
Traffic log service: write and query traffic logs.
"""

from datetime import datetime
from typing import Any

from app.db.database import get_db
from app.db.models import TrafficLog


def add_log(
    src_ip: str | None = None,
    dst_ip: str | None = None,
    protocol: str | None = None,
    src_port: int | None = None,
    dst_port: int | None = None,
    length: int | None = None,
    action: str = "ALLOW",
    rule_id: int | None = None,
    reason: str | None = None,
    timestamp: datetime | None = None,
) -> TrafficLog:
    db = get_db()
    try:
        log = TrafficLog(
            timestamp=timestamp or datetime.utcnow(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            action=action,
            rule_id=rule_id,
            reason=reason,
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return log
    finally:
        db.close()


def get_logs(
    limit: int = 100,
    offset: int = 0,
    src_ip: str | None = None,
    action: str | None = None,
) -> list[TrafficLog]:
    db = get_db()
    try:
        q = db.query(TrafficLog).order_by(TrafficLog.id.desc())
        if src_ip:
            q = q.filter(TrafficLog.src_ip == src_ip)
        if action:
            q = q.filter(TrafficLog.action == action)
        return q.offset(offset).limit(limit).all()
    finally:
        db.close()


def get_logs_count(src_ip: str | None = None, action: str | None = None) -> int:
    db = get_db()
    try:
        q = db.query(TrafficLog)
        if src_ip:
            q = q.filter(TrafficLog.src_ip == src_ip)
        if action:
            q = q.filter(TrafficLog.action == action)
        return q.count()
    finally:
        db.close()
