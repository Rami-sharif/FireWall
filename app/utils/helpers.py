"""
Helper utilities: safe subprocess, IP list loading, timestamps, matching.
"""

import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path


def run_safe(
    cmd: list[str],
    timeout_sec: int = 5,
    cwd: str | None = None,
) -> tuple[bool, str]:
    """
    Run a command via subprocess (no shell). Returns (success, output_or_error).
    Used by enforcer for iptables; avoids shell=True.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            cwd=cwd,
        )
        if result.returncode == 0:
            return True, result.stdout or ""
        return False, result.stderr or result.stdout or f"exit code {result.returncode}"
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError:
        return False, "Command not found"
    except Exception as e:
        return False, str(e)


def load_ip_list(filepath: str) -> set[str]:
    """
    Load IP addresses from a file (one per line). Returns empty set if file missing.
    """
    path = Path(filepath)
    if not path.exists():
        return set()
    ips = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ips.add(line)
    return ips


def is_valid_ip(ip: str) -> bool:
    """Simple IPv4 check."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_cidr(spec: str) -> bool:
    """Return True if spec is a valid CIDR network or IP address."""
    try:
        ipaddress.ip_network(spec, strict=False)
        return True
    except ValueError:
        return False


def parse_port_spec(spec: str | None) -> set[int] | None:
    """
    Parse port specification into a set of port ints.
    Supports:
      - None / empty / "*" / "any" → any (returns None)
      - single: "80"
      - comma-separated: "80,443"
      - range: "1024-65535"
      - mixed: "22,80,8000-8080"
    """
    if spec is None or (isinstance(spec, str) and not spec.strip()):
        return None
    s = str(spec).strip()
    if s in ("*", "any", "ALL", "all"):
        return None
    ports: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            try:
                lo, hi = int(lo_s.strip()), int(hi_s.strip())
                ports.update(range(lo, hi + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return ports if ports else None


def match_port(port_spec: set[int] | None, port: int | None) -> bool:
    """True if port_spec is None (any) or port is in port_spec.
    Returns False when the rule specifies ports but the packet carries none (e.g. ICMP)."""
    if port_spec is None:
        return True
    if port is None:
        return False  # rule requires a specific port; packet has none
    return port in port_spec


def match_ip_spec(spec: str | None, ip: str | None) -> bool:
    """
    True if spec is None/empty/wildcard or ip matches spec.
    Supports:
      - None / "" / "*"   → match any
      - exact IP          → exact match
      - CIDR "10.0.0.0/8" → subnet membership
    """
    if spec is None or not spec.strip() or spec.strip() == "*":
        return True
    if ip is None:
        return True
    s = spec.strip()
    # CIDR check
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
            return ipaddress.ip_address(ip) in net
        except ValueError:
            return False
    # Exact match
    return ip == s


def validate_ip_spec(spec: str) -> bool:
    """Return True if spec is a valid IP, CIDR, or wildcard."""
    s = spec.strip()
    if not s or s == "*":
        return True
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def validate_port_spec(spec: str) -> bool:
    """Return True if spec is a valid port specification."""
    if not spec or not spec.strip():
        return True
    if spec.strip() in ("*", "any", "ANY", "all", "ALL"):
        return True
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
                if not (0 <= lo <= 65535 and 0 <= hi <= 65535 and lo <= hi):
                    return False
            except ValueError:
                return False
        else:
            try:
                p = int(part)
                if not 0 <= p <= 65535:
                    return False
            except ValueError:
                return False
    return True


def validate_regex(pattern: str) -> tuple[bool, str]:
    """Return (valid, error_message). error_message is '' when valid."""
    try:
        re.compile(pattern)
        return True, ""
    except re.error as e:
        return False, str(e)


def payload_safe_summary(raw: bytes | str, max_len: int = 200) -> str:
    """Produce a string summary of payload for logging (avoid binary)."""
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            text = str(raw)[:max_len]
    else:
        text = str(raw)
    text = "".join(c if c.isprintable() or c in "\n\r\t" else "." for c in text)
    return text[:max_len]


def require_root_linux() -> bool:
    """Return True if on Linux and we have root (euid 0). On non-Linux, returns True (not applicable)."""
    if sys.platform != "linux":
        return True
    if not hasattr(os, "geteuid"):
        return False
    return os.geteuid() == 0
