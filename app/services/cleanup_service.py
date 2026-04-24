"""
Cleanup service: bulk deletion of traffic logs and alerts with various filters.
All operations return {"deleted": int}.
"""

import os
from datetime import datetime, timedelta

from sqlalchemy import and_

from app.db.database import get_db
from app.db.models import Alert, TrafficLog
from app.utils.config import get_config
from app.utils.logger import get_logger

logger = get_logger(__name__)


def _parse_date(date_str: str) -> datetime:
    """Parse ISO date string to datetime. Raises ValueError on bad format."""
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse date: {date_str!r}. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS")


# ── Traffic Log deletions ─────────────────────────────────────────────────────

def delete_all_logs() -> dict:
    db = get_db()
    try:
        count = db.query(TrafficLog).delete()
        db.commit()
        logger.info("Deleted all %d traffic logs", count)
        return {"deleted": count}
    finally:
        db.close()


def delete_logs_before(date_str: str) -> dict:
    cutoff = _parse_date(date_str)
    db = get_db()
    try:
        count = db.query(TrafficLog).filter(TrafficLog.timestamp < cutoff).delete()
        db.commit()
        logger.info("Deleted %d traffic logs before %s", count, cutoff)
        return {"deleted": count}
    finally:
        db.close()


def delete_logs_by_ip(src_ip: str) -> dict:
    db = get_db()
    try:
        count = db.query(TrafficLog).filter(TrafficLog.src_ip == src_ip).delete()
        db.commit()
        logger.info("Deleted %d traffic logs for IP %s", count, src_ip)
        return {"deleted": count}
    finally:
        db.close()


def delete_logs_by_action(action: str) -> dict:
    db = get_db()
    try:
        count = db.query(TrafficLog).filter(TrafficLog.action == action.upper()).delete()
        db.commit()
        logger.info("Deleted %d traffic logs with action %s", count, action)
        return {"deleted": count}
    finally:
        db.close()


def delete_logs_by_protocol(protocol: str) -> dict:
    db = get_db()
    try:
        count = db.query(TrafficLog).filter(
            TrafficLog.protocol == protocol.upper()
        ).delete()
        db.commit()
        logger.info("Deleted %d traffic logs for protocol %s", count, protocol)
        return {"deleted": count}
    finally:
        db.close()


def delete_logs_by_dst_ip(dst_ip: str) -> dict:
    db = get_db()
    try:
        count = db.query(TrafficLog).filter(TrafficLog.dst_ip == dst_ip).delete()
        db.commit()
        logger.info("Deleted %d traffic logs for dst IP %s", count, dst_ip)
        return {"deleted": count}
    finally:
        db.close()


def delete_logs_date_range(start_str: str, end_str: str) -> dict:
    start = _parse_date(start_str)
    end = _parse_date(end_str)
    db = get_db()
    try:
        count = db.query(TrafficLog).filter(
            and_(TrafficLog.timestamp >= start, TrafficLog.timestamp <= end)
        ).delete()
        db.commit()
        logger.info("Deleted %d traffic logs between %s and %s", count, start, end)
        return {"deleted": count}
    finally:
        db.close()


def delete_logs_older_than_days(days: int) -> dict:
    cutoff = datetime.utcnow() - timedelta(days=days)
    db = get_db()
    try:
        count = db.query(TrafficLog).filter(TrafficLog.timestamp < cutoff).delete()
        db.commit()
        logger.info("Deleted %d traffic logs older than %d days", count, days)
        return {"deleted": count}
    finally:
        db.close()


# ── Alert deletions ───────────────────────────────────────────────────────────

def delete_all_alerts() -> dict:
    db = get_db()
    try:
        count = db.query(Alert).delete()
        db.commit()
        logger.info("Deleted all %d alerts", count)
        return {"deleted": count}
    finally:
        db.close()


def delete_alerts_before(date_str: str) -> dict:
    cutoff = _parse_date(date_str)
    db = get_db()
    try:
        count = db.query(Alert).filter(Alert.timestamp < cutoff).delete()
        db.commit()
        logger.info("Deleted %d alerts before %s", count, cutoff)
        return {"deleted": count}
    finally:
        db.close()


def delete_alerts_by_severity(severity: str) -> dict:
    db = get_db()
    try:
        count = db.query(Alert).filter(Alert.severity == severity.lower()).delete()
        db.commit()
        logger.info("Deleted %d alerts with severity %s", count, severity)
        return {"deleted": count}
    finally:
        db.close()


def delete_alerts_older_than_days(days: int) -> dict:
    cutoff = datetime.utcnow() - timedelta(days=days)
    db = get_db()
    try:
        count = db.query(Alert).filter(Alert.timestamp < cutoff).delete()
        db.commit()
        logger.info("Deleted %d alerts older than %d days", count, days)
        return {"deleted": count}
    finally:
        db.close()


# ── Data-usage stats ──────────────────────────────────────────────────────────

def get_data_usage() -> dict:
    """Return record counts and DB file size."""
    db = get_db()
    try:
        log_count = db.query(TrafficLog).count()
        alert_count = db.query(Alert).count()
        from app.db.models import Rule
        rule_count = db.query(Rule).count()
    finally:
        db.close()

    cfg = get_config()
    db_path = cfg.get("DB_PATH", "")
    try:
        db_size_bytes = os.path.getsize(db_path)
    except OSError:
        db_size_bytes = 0

    return {
        "db_size_bytes": db_size_bytes,
        "db_size_mb": round(db_size_bytes / (1024 * 1024), 3),
        "log_count": log_count,
        "alert_count": alert_count,
        "rule_count": rule_count,
    }
