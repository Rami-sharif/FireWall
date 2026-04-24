"""
Rule engine: evaluate packet against rules (by priority), whitelist, blacklist; return decision.
Supports: exact IP, CIDR, port ranges, regex/substring payload matching, TCP flags, rate-limit tags.
"""

import re
from datetime import datetime
from typing import Any

from app.services.rule_service import get_all_rules
from app.utils.constants import (
    ACTION_ALLOW,
    ACTION_ALERT,
    ACTION_BLOCK,
    ACTION_LOG_ONLY,
    ACTIONS,
    DETECTION_RATE_LIMIT,
)
from app.utils.config import get_config
from app.utils.helpers import load_ip_list, match_port, match_ip_spec, parse_port_spec


def _payload_matches(rule: Any, payload: str) -> bool:
    """Match payload against rule's pattern (regex or substring, case-sensitive or not)."""
    pattern = rule.payload_pattern
    if not pattern:
        return True
    case_sensitive = bool(getattr(rule, "match_case_sensitive", False))
    use_regex = bool(getattr(rule, "payload_regex", False))
    if use_regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            return bool(re.search(pattern, payload, flags))
        except re.error:
            return False
    else:
        if case_sensitive:
            return pattern in payload
        return pattern.lower() in payload.lower()


def _in_time_range(time_range: str | None) -> bool:
    """
    Return True if current time is within time_range (format "HH:MM-HH:MM").
    Returns True when time_range is None (no restriction).
    """
    if not time_range:
        return True
    try:
        start_s, end_s = time_range.strip().split("-")
        now = datetime.now().time()
        sh, sm = map(int, start_s.split(":"))
        eh, em = map(int, end_s.split(":"))
        from datetime import time as dtime
        start = dtime(sh, sm)
        end = dtime(eh, em)
        if start <= end:
            return start <= now <= end
        # Wraps midnight
        return now >= start or now <= end
    except Exception:
        return True


def _rule_matches(rule: Any, parsed: dict[str, Any], detection_tags: list[str]) -> bool:
    """Return True if the rule matches the parsed packet (and optional detector tags)."""
    if not match_ip_spec(rule.src_ip, parsed.get("src_ip")):
        return False
    if not match_ip_spec(rule.dst_ip, parsed.get("dst_ip")):
        return False
    if rule.protocol and (rule.protocol.upper() != (parsed.get("protocol") or "").upper()):
        return False
    src_ports = parse_port_spec(rule.src_port)
    if not match_port(src_ports, parsed.get("src_port")):
        return False
    dst_ports = parse_port_spec(rule.dst_port)
    if not match_port(dst_ports, parsed.get("dst_port")):
        return False
    if rule.payload_pattern:
        payload = parsed.get("payload_summary") or ""
        if not _payload_matches(rule, payload):
            return False
    if rule.tcp_flags:
        flags = (parsed.get("tcp_flags") or "")
        for f in rule.tcp_flags.split(","):
            f = f.strip().upper()
            if f and f not in flags:
                return False
    if rule.rate_limit is not None and rule.rate_limit > 0:
        if DETECTION_RATE_LIMIT not in detection_tags:
            return False
    # Time-range restriction (attribute may not exist on older Rule rows)
    time_range = getattr(rule, "time_range", None)
    if not _in_time_range(time_range):
        return False
    return True


def evaluate(parsed: dict[str, Any], detection_tags: list[str]) -> dict[str, Any]:
    """
    Evaluate packet against whitelist, blacklist, then rules by priority.
    Returns: { "action": "ALLOW"|"BLOCK"|"ALERT"|"LOG_ONLY", "rule_id": int|None, "reason": str }.
    """
    config = get_config()
    whitelist = load_ip_list(config["WHITELIST_PATH"])
    blacklist = load_ip_list(config["BLACKLIST_PATH"])
    src_ip = parsed.get("src_ip")

    if src_ip and src_ip in whitelist:
        return {"action": ACTION_ALLOW, "rule_id": None, "reason": "whitelist"}

    if src_ip and src_ip in blacklist:
        return {"action": ACTION_BLOCK, "rule_id": None, "reason": "blacklist"}

    rules = get_all_rules(enabled_only=True)
    for rule in rules:
        if getattr(rule, "is_archived", False):
            continue
        if _rule_matches(rule, parsed, detection_tags):
            action = (rule.action or ACTION_ALLOW).upper()
            if action not in ACTIONS:
                action = ACTION_ALLOW
            return {
                "action": action,
                "rule_id": rule.id,
                "reason": rule.name or f"rule_{rule.id}",
            }

    return {"action": ACTION_ALLOW, "rule_id": None, "reason": "default"}
