"""
SQLAlchemy models for the Smart Firewall Simulation Platform.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_group: Mapped[str | None] = mapped_column(String(100), nullable=True)
    rule_tags: Mapped[dict | None] = mapped_column(JSON, nullable=True)           # list of str
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    src_port: Mapped[str | None] = mapped_column(String(100), nullable=True)      # e.g. "80,443" or "1024-65535"
    dst_port: Mapped[str | None] = mapped_column(String(100), nullable=True)
    rate_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    payload_pattern: Mapped[str | None] = mapped_column(String(500), nullable=True)
    payload_regex: Mapped[bool] = mapped_column(Boolean, default=False)           # treat pattern as regex
    match_case_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    log_payload: Mapped[bool] = mapped_column(Boolean, default=False)
    tcp_flags: Mapped[str | None] = mapped_column(String(50), nullable=True)
    action: Mapped[str] = mapped_column(String(20), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    is_archived: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    change_log: Mapped[dict | None] = mapped_column(JSON, nullable=True)          # list of change entries
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, onupdate=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "rule_group": self.rule_group,
            "rule_tags": self.rule_tags or [],
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "rate_limit": self.rate_limit,
            "payload_pattern": self.payload_pattern,
            "payload_regex": self.payload_regex,
            "match_case_sensitive": self.match_case_sensitive,
            "log_payload": self.log_payload,
            "tcp_flags": self.tcp_flags,
            "action": self.action,
            "priority": self.priority,
            "enabled": self.enabled,
            "is_archived": self.is_archived,
            "version": self.version,
            "change_log": self.change_log or [],
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class TrafficLog(Base):
    __tablename__ = "traffic_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    src_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True, index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    length: Mapped[int | None] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    rule_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "length": self.length,
            "action": self.action,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    detection_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "message": self.message,
            "detection_type": self.detection_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class TrafficStats(Base):
    __tablename__ = "traffic_stats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    period_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    total_packets: Mapped[int] = mapped_column(Integer, default=0)
    allowed_count: Mapped[int] = mapped_column(Integer, default=0)
    blocked_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    protocol_breakdown: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "period_start": self.period_start.isoformat() if self.period_start else None,
            "period_end": self.period_end.isoformat() if self.period_end else None,
            "total_packets": self.total_packets,
            "allowed_count": self.allowed_count,
            "blocked_count": self.blocked_count,
            "alert_count": self.alert_count,
            "protocol_breakdown": self.protocol_breakdown,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class BlockedHost(Base):
    __tablename__ = "blocked_hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False)
    blocked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ip": self.ip,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
            "reason": self.reason,
        }


class SystemConfig(Base):
    __tablename__ = "system_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    value: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "value": self.value,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
