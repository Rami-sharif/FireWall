"""
Enforcement abstraction: the only place system-level blocking (e.g. iptables) is performed.
No-op when simulation mode or enforcement disabled. Uses subprocess with timeout; Linux only.
"""

import sys

from app.utils.config import get_config
from app.utils.helpers import run_safe, require_root_linux
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Tag added to every iptables rule so we can find and flush them on startup,
# even if the previous session was killed and _blocked_ips was lost.
_RULE_COMMENT = "firewall-app"

# Track IPs blocked during this session so they can be removed on cleanup
_blocked_ips: set[str] = set()


def _flush_tagged_rules() -> None:
    """
    Remove every INPUT rule tagged with _RULE_COMMENT from iptables.
    Works even after a crash — finds rules by comment, not in-memory state.
    """
    if sys.platform != "linux" or not require_root_linux():
        return
    timeout = get_config().get("SUBPROCESS_TIMEOUT_SEC", 5)
    # Loop because rule numbers shift after each deletion; keep deleting until none left.
    for _ in range(500):  # safety cap
        ok, out = run_safe(
            ["iptables", "-L", "INPUT", "--line-numbers", "-n"],
            timeout_sec=timeout,
        )
        if not ok:
            break
        line_num = None
        for line in out.splitlines():
            if _RULE_COMMENT in line:
                parts = line.split()
                if parts and parts[0].isdigit():
                    line_num = parts[0]
                    break
        if line_num is None:
            break  # no more tagged rules
        run_safe(["iptables", "-D", "INPUT", line_num], timeout_sec=timeout)
    logger.info("Flushed all iptables rules tagged '%s'", _RULE_COMMENT)


def apply_block(ip: str) -> bool:
    """
    If enforcement is enabled (and not simulation), attempt to block the IP at OS level.
    On Linux: runs iptables -I INPUT 1 -s <ip> -j DROP (tagged with a comment) via subprocess.
    Returns True if blocking was attempted and succeeded, False otherwise.
    """
    config = get_config()
    if config.get("SIMULATION_MODE", True):
        return False
    if not config.get("ENFORCEMENT_ENABLED", False):
        return False
    if sys.platform != "linux":
        logger.warning("Enforcement is only supported on Linux; skipping block for %s", ip)
        return False
    if not require_root_linux():
        logger.warning("Enforcement requires root on Linux; skipping block for %s", ip)
        return False
    timeout = config.get("SUBPROCESS_TIMEOUT_SEC", 5)
    ok, out = run_safe(
        ["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP",
         "-m", "comment", "--comment", _RULE_COMMENT],
        timeout_sec=timeout,
    )
    if ok:
        _blocked_ips.add(ip)
        logger.info("Blocked IP %s via iptables", ip)
        return True
    logger.error("Failed to block IP %s: %s", ip, out)
    return False


def remove_block(ip: str) -> bool:
    """Remove a previously added iptables DROP rule for this IP."""
    if sys.platform != "linux" or not require_root_linux():
        return False
    timeout = get_config().get("SUBPROCESS_TIMEOUT_SEC", 5)
    ok, out = run_safe(
        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
         "-m", "comment", "--comment", _RULE_COMMENT],
        timeout_sec=timeout,
    )
    if ok:
        _blocked_ips.discard(ip)
        logger.info("Unblocked IP %s via iptables", ip)
    else:
        logger.warning("Failed to unblock IP %s: %s", ip, out)
    return ok


def cleanup_all_blocks() -> None:
    """
    Remove all iptables rules added by this app — both tracked in-memory and
    any orphaned rules from a previous crashed session (found via comment tag).
    Safe to call on shutdown or at startup.
    """
    if sys.platform != "linux" or not require_root_linux():
        return
    # Fast per-IP removal for currently tracked IPs
    for ip in list(_blocked_ips):
        remove_block(ip)
    # Full tagged-rule sweep to catch anything missed (crash/kill survivors)
    _flush_tagged_rules()
    logger.info("Enforcement cleanup complete")
