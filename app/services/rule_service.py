"""
Rule CRUD, cloning, versioned updates, import/export, and loading from JSON.
"""

import csv
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from app.db.database import get_db
from app.db.models import Rule
from app.utils.constants import ACTION_ALLOW, ACTIONS


# ── Internal helpers ──────────────────────────────────────────────────────────

def _record_change(rule: Rule, change_type: str, before: dict | None, after: dict) -> None:
    """Append a change entry to rule.change_log."""
    entry = {
        "type": change_type,
        "at": datetime.utcnow().isoformat(),
        "before": before,
        "after": after,
    }
    log = list(rule.change_log or [])
    log.append(entry)
    rule.change_log = log
    rule.version = (rule.version or 1) + 1


def _clean_action(action: str | None) -> str:
    a = (action or ACTION_ALLOW).upper()
    return a if a in ACTIONS else ACTION_ALLOW


def _apply_fields(rule: Rule, data: dict) -> None:
    """Apply all mutable data fields to a Rule object."""
    if "name" in data:
        rule.name = data["name"] or "Unnamed"
    if "description" in data:
        rule.description = data.get("description") or None
    if "rule_group" in data:
        rule.rule_group = data.get("rule_group") or None
    if "rule_tags" in data:
        tags = data.get("rule_tags")
        rule.rule_tags = tags if isinstance(tags, list) else []
    if "src_ip" in data:
        rule.src_ip = data["src_ip"] or None
    if "dst_ip" in data:
        rule.dst_ip = data["dst_ip"] or None
    if "protocol" in data:
        rule.protocol = data["protocol"] or None
    if "src_port" in data:
        rule.src_port = str(data["src_port"]) if data["src_port"] is not None else None
    if "dst_port" in data:
        rule.dst_port = str(data["dst_port"]) if data["dst_port"] is not None else None
    if "rate_limit" in data:
        rule.rate_limit = data["rate_limit"]
    if "payload_pattern" in data:
        rule.payload_pattern = data["payload_pattern"] or None
    if "payload_regex" in data:
        rule.payload_regex = bool(data["payload_regex"])
    if "match_case_sensitive" in data:
        rule.match_case_sensitive = bool(data["match_case_sensitive"])
    if "log_payload" in data:
        rule.log_payload = bool(data["log_payload"])
    if "tcp_flags" in data:
        rule.tcp_flags = data["tcp_flags"] or None
    if "action" in data:
        rule.action = _clean_action(data["action"])
    if "priority" in data:
        rule.priority = int(data["priority"])
    if "enabled" in data:
        rule.enabled = bool(data["enabled"])


# ── Queries ───────────────────────────────────────────────────────────────────

def get_all_rules(enabled_only: bool = False, include_archived: bool = False) -> list[Rule]:
    db = get_db()
    try:
        q = db.query(Rule).order_by(Rule.priority.asc(), Rule.id.asc())
        if enabled_only:
            q = q.filter(Rule.enabled == True)
        if not include_archived:
            q = q.filter(Rule.is_archived == False)
        return q.all()
    finally:
        db.close()


def get_rule_by_id(rule_id: int) -> Rule | None:
    db = get_db()
    try:
        return db.query(Rule).filter(Rule.id == rule_id).first()
    finally:
        db.close()


def get_all_tags() -> list[str]:
    """Collect and sort all unique tags across non-archived rules."""
    db = get_db()
    try:
        rules = db.query(Rule).filter(Rule.is_archived == False).all()
        tags: set[str] = set()
        for r in rules:
            for t in (r.rule_tags or []):
                tags.add(str(t))
        return sorted(tags)
    finally:
        db.close()


def get_all_groups() -> list[str]:
    """Collect all unique non-null rule_group values."""
    db = get_db()
    try:
        rows = db.query(Rule.rule_group).filter(
            Rule.rule_group != None,
            Rule.is_archived == False,
        ).distinct().all()
        return sorted(r[0] for r in rows if r[0])
    finally:
        db.close()


# ── Create / Update / Delete ──────────────────────────────────────────────────

def create_rule(data: dict[str, Any]) -> Rule:
    db = get_db()
    try:
        r = Rule(
            name=data.get("name") or "Unnamed",
            action=_clean_action(data.get("action")),
            priority=int(data.get("priority", 100)),
            enabled=bool(data.get("enabled", True)),
            version=1,
            change_log=[],
        )
        _apply_fields(r, data)
        db.add(r)
        db.commit()
        db.refresh(r)
        return r
    finally:
        db.close()


def update_rule(rule_id: int, data: dict[str, Any]) -> Rule | None:
    db = get_db()
    try:
        r = db.query(Rule).filter(Rule.id == rule_id).first()
        if not r:
            return None
        before = r.to_dict()
        _apply_fields(r, data)
        _record_change(r, "update", before, {k: v for k, v in data.items()})
        db.commit()
        db.refresh(r)
        return r
    finally:
        db.close()


def patch_rule_enabled(rule_id: int, enabled: bool) -> Rule | None:
    db = get_db()
    try:
        r = db.query(Rule).filter(Rule.id == rule_id).first()
        if not r:
            return None
        before = {"enabled": r.enabled}
        r.enabled = enabled
        _record_change(r, "toggle_enabled", before, {"enabled": enabled})
        db.commit()
        db.refresh(r)
        return r
    finally:
        db.close()


def patch_rule_priority(rule_id: int, priority: int) -> Rule | None:
    db = get_db()
    try:
        r = db.query(Rule).filter(Rule.id == rule_id).first()
        if not r:
            return None
        before = {"priority": r.priority}
        r.priority = priority
        _record_change(r, "update_priority", before, {"priority": priority})
        db.commit()
        db.refresh(r)
        return r
    finally:
        db.close()


def patch_rule_tags(rule_id: int, tags: list[str]) -> Rule | None:
    db = get_db()
    try:
        r = db.query(Rule).filter(Rule.id == rule_id).first()
        if not r:
            return None
        before = {"rule_tags": r.rule_tags}
        r.rule_tags = tags
        _record_change(r, "update_tags", before, {"rule_tags": tags})
        db.commit()
        db.refresh(r)
        return r
    finally:
        db.close()


def delete_rule(rule_id: int) -> bool:
    db = get_db()
    try:
        r = db.query(Rule).filter(Rule.id == rule_id).first()
        if not r:
            return False
        db.delete(r)
        db.commit()
        return True
    finally:
        db.close()


def archive_rule(rule_id: int) -> Rule | None:
    db = get_db()
    try:
        r = db.query(Rule).filter(Rule.id == rule_id).first()
        if not r:
            return None
        before = {"is_archived": r.is_archived}
        r.is_archived = True
        r.enabled = False
        _record_change(r, "archive", before, {"is_archived": True})
        db.commit()
        db.refresh(r)
        return r
    finally:
        db.close()


# ── Clone ─────────────────────────────────────────────────────────────────────

def clone_rule(rule_id: int, new_name: str | None = None) -> Rule | None:
    db = get_db()
    try:
        src = db.query(Rule).filter(Rule.id == rule_id).first()
        if not src:
            return None
        data = src.to_dict()
        data.pop("id", None)
        data.pop("created_at", None)
        data.pop("updated_at", None)
        data["name"] = new_name or f"Copy of {src.name}"
        data["version"] = 1
        data["change_log"] = []
        data["is_archived"] = False
        r = Rule(
            name=data["name"],
            action=src.action,
            priority=src.priority,
            enabled=False,  # clones start disabled
            version=1,
            change_log=[],
        )
        _apply_fields(r, data)
        r.enabled = False
        db.add(r)
        db.commit()
        db.refresh(r)
        return r
    finally:
        db.close()


# ── History ───────────────────────────────────────────────────────────────────

def get_rule_history(rule_id: int) -> list[dict] | None:
    db = get_db()
    try:
        r = db.query(Rule).filter(Rule.id == rule_id).first()
        if not r:
            return None
        return list(r.change_log or [])
    finally:
        db.close()


# ── Validate ──────────────────────────────────────────────────────────────────

def validate_rule_data(data: dict) -> dict:
    """Return {"valid": bool, "errors": list[str]}."""
    from app.utils.helpers import validate_ip_spec, validate_port_spec, validate_regex
    errors = []
    if not data.get("name"):
        errors.append("name is required")
    action = (data.get("action") or "").upper()
    if action and action not in ACTIONS:
        errors.append(f"action must be one of {ACTIONS}")
    for field in ("src_ip", "dst_ip"):
        val = data.get(field)
        if val and not validate_ip_spec(val):
            errors.append(f"{field}: invalid IP or CIDR '{val}'")
    for field in ("src_port", "dst_port"):
        val = data.get(field)
        if val and not validate_port_spec(str(val)):
            errors.append(f"{field}: invalid port spec '{val}'")
    if data.get("payload_regex") and data.get("payload_pattern"):
        ok, err = validate_regex(data["payload_pattern"])
        if not ok:
            errors.append(f"payload_pattern is invalid regex: {err}")
    try:
        prio = int(data.get("priority", 100))
        if not 0 <= prio <= 9999:
            errors.append("priority must be 0–9999")
    except (TypeError, ValueError):
        errors.append("priority must be an integer")
    return {"valid": len(errors) == 0, "errors": errors}


# ── Bulk create ───────────────────────────────────────────────────────────────

def bulk_create_rules(items: list[dict]) -> dict:
    """Create multiple rules. Returns {created: int, errors: list}."""
    created = 0
    errors = []
    for i, item in enumerate(items):
        validation = validate_rule_data(item)
        if not validation["valid"]:
            errors.append({"index": i, "name": item.get("name"), "errors": validation["errors"]})
            continue
        try:
            create_rule(item)
            created += 1
        except Exception as e:
            errors.append({"index": i, "name": item.get("name"), "errors": [str(e)]})
    return {"created": created, "errors": errors}


# ── Export ────────────────────────────────────────────────────────────────────

def export_rules_json(include_archived: bool = False) -> str:
    rules = get_all_rules(include_archived=include_archived)
    return json.dumps([r.to_dict() for r in rules], indent=2)


def export_rules_csv(include_archived: bool = False) -> str:
    rules = get_all_rules(include_archived=include_archived)
    output = io.StringIO()
    fieldnames = [
        "id", "name", "description", "rule_group", "src_ip", "dst_ip",
        "protocol", "src_port", "dst_port", "payload_pattern", "payload_regex",
        "tcp_flags", "action", "priority", "enabled", "is_archived", "created_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in rules:
        row = r.to_dict()
        row["rule_tags"] = json.dumps(row.get("rule_tags", []))
        writer.writerow(row)
    return output.getvalue()


# ── Import ────────────────────────────────────────────────────────────────────

def import_rules_json(raw: str) -> dict:
    """Parse JSON string and bulk-create rules. Returns summary."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        return {"created": 0, "errors": [{"index": -1, "errors": [f"JSON parse error: {e}"]}]}
    items = data if isinstance(data, list) else data.get("rules", [])
    return bulk_create_rules(items)


def import_rules_csv(raw: str) -> dict:
    """Parse CSV string and bulk-create rules."""
    reader = csv.DictReader(io.StringIO(raw))
    items = list(reader)
    return bulk_create_rules(items)


# ── Load from JSON file (startup) ─────────────────────────────────────────────

def load_rules_from_json(filepath: str) -> list[Rule]:
    """Load rules from JSON file and insert into DB (by name: skip if exists)."""
    path = Path(filepath)
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    rules_list = raw if isinstance(raw, list) else raw.get("rules", [])
    created = []
    db = get_db()
    try:
        for item in rules_list:
            name = item.get("name") or "Imported"
            existing = db.query(Rule).filter(Rule.name == name).first()
            if existing:
                continue
            r = Rule(
                name=name,
                src_ip=item.get("src_ip"),
                dst_ip=item.get("dst_ip"),
                protocol=item.get("protocol"),
                src_port=str(item["src_port"]) if item.get("src_port") is not None else None,
                dst_port=str(item["dst_port"]) if item.get("dst_port") is not None else None,
                rate_limit=item.get("rate_limit"),
                payload_pattern=item.get("payload_pattern"),
                tcp_flags=item.get("tcp_flags"),
                action=_clean_action(item.get("action")),
                priority=int(item.get("priority", 100)),
                enabled=bool(item.get("enabled", True)),
                version=1,
                change_log=[],
            )
            db.add(r)
            created.append(r)
        db.commit()
        for r in created:
            db.refresh(r)
        return created
    finally:
        db.close()
