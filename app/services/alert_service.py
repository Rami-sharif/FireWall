"""
Alert service: create and query alerts.
"""

from datetime import datetime
from typing import Any

from app.db.database import get_db
from app.db.models import Alert
from app.utils.constants import SEVERITY_MEDIUM


def create_alert(
    message: str,
    severity: str = SEVERITY_MEDIUM,
    source_ip: str | None = None,
    detection_type: str | None = None,
    timestamp: datetime | None = None,
) -> Alert:
    db = get_db()
    try:
        alert = Alert(
            timestamp=timestamp or datetime.utcnow(),
            severity=severity,
            source_ip=source_ip,
            message=message,
            detection_type=detection_type,
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert
    finally:
        db.close()


def get_alerts(
    limit: int = 100,
    offset: int = 0,
    severity: str | None = None,
) -> list[Alert]:
    db = get_db()
    try:
        q = db.query(Alert).order_by(Alert.id.desc())
        if severity:
            q = q.filter(Alert.severity == severity)
        return q.offset(offset).limit(limit).all()
    finally:
        db.close()


def get_alerts_count(severity: str | None = None) -> int:
    db = get_db()
    try:
        q = db.query(Alert)
        if severity:
            q = q.filter(Alert.severity == severity)
        return q.count()
    finally:
        db.close()
