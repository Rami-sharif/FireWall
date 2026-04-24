"""
Runtime state tracking for firewall/IDS: blocked IPs, packet counts, detection windows.
Used by detector and enforcer; supports persistence of blocked IPs to file.
"""

import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from app.utils.config import get_config
from app.utils.helpers import load_ip_list


class FirewallState:
    """
    In-memory state for detection and blocking.
    - blocked_ips: set of IPs currently considered blocked (loaded from file + runtime)
    - packet counts, SYN/ICMP/DNS per source IP in time windows
    - port scan: distinct ports per source in window
    - slowloris: count of incomplete/long-lived connections per IP
    - botnet: recent unique source IPs (for many-IPs-in-short-time pattern)
    - stats: total_packets, allowed_count, blocked_count, alert_count
    """

    def __init__(self) -> None:
        self._config = get_config()
        self._blocked_ips: set[str] = set()
        self._block_reasons: dict[str, str] = {}  # ip -> reason
        # Rate: per src_ip, deque of timestamps
        self._rate_timestamps: dict[str, deque[float]] = defaultdict(deque)
        self._syn_timestamps: dict[str, deque[float]] = defaultdict(deque)
        self._icmp_timestamps: dict[str, deque[float]] = defaultdict(deque)
        self._dns_timestamps: dict[str, deque[float]] = defaultdict(deque)
        # Port scan: per src_ip, deque of (timestamp, dst_port)
        self._port_scan_events: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        # Slowloris: per src_ip, count of "incomplete" connections in window (e.g. SYN no complete HTTP)
        self._slowloris_events: dict[str, deque[float]] = defaultdict(deque)
        # Botnet: global deque of (timestamp, src_ip) to detect many IPs in short time
        self._botnet_src_timestamps: deque[tuple[float, str]] = deque()
        # Payload/SQLi hit count per IP (for repeated suspicious payload)
        self._suspicious_payload_hits: dict[str, int] = defaultdict(int)
        # Stats
        self._total_packets = 0
        self._allowed_count = 0
        self._blocked_count = 0
        self._alert_count = 0
        self._last_cleanup = time.time()
        self._cleanup_interval = 60.0
        self._load_blocked_ips_file()

    def _load_blocked_ips_file(self) -> None:
        """Load initially blocked IPs from config file path."""
        path = self._config.get("BLOCKED_IP_FILE")
        if not path:
            return
        p = Path(path)
        if not p.exists():
            return
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                # Optional format: IP  or  IP # reason
                ip = line.split("#")[0].strip().split()[0] if line else ""
                if ip:
                    self._blocked_ips.add(ip)

    def save_blocked_ip(self, ip: str, reason: str = "") -> None:
        """Add IP to blocked set and append to file."""
        if ip in self._blocked_ips:
            return
        self._blocked_ips.add(ip)
        self._block_reasons[ip] = reason
        path = self._config.get("BLOCKED_IP_FILE")
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            try:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(f"{ip}  # {reason}\n")
            except OSError:
                pass

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked_ips

    def get_block_reason(self, ip: str) -> str:
        return self._block_reasons.get(ip, "blocked")

    def record_packet(self, parsed: dict[str, Any]) -> None:
        """Update per-IP and global counters for a parsed packet."""
        src = parsed.get("src_ip")
        if not src:
            return
        now = time.time()
        self._total_packets += 1
        self._rate_timestamps[src].append(now)
        if parsed.get("protocol") == "TCP":
            flags = parsed.get("tcp_flags") or ""
            if "SYN" in flags:
                self._syn_timestamps[src].append(now)
        if parsed.get("protocol") == "ICMP":
            self._icmp_timestamps[src].append(now)
        if parsed.get("protocol") == "UDP" and parsed.get("dst_port") == 53:
            self._dns_timestamps[src].append(now)
        dst_port = parsed.get("dst_port")
        if dst_port is not None:
            self._port_scan_events[src].append((now, dst_port))
        self._botnet_src_timestamps.append((now, src))

    def record_allow(self) -> None:
        self._allowed_count += 1

    def record_block(self) -> None:
        self._blocked_count += 1

    def record_alert(self) -> None:
        self._alert_count += 1

    def record_slowloris_connection(self, src_ip: str) -> None:
        self._slowloris_events[src_ip].append(time.time())

    def record_suspicious_payload_hit(self, src_ip: str) -> None:
        self._suspicious_payload_hits[src_ip] += 1

    def get_rate_count(self, src_ip: str, window_sec: float) -> int:
        now = time.time()
        q = self._rate_timestamps[src_ip]
        while q and (now - q[0]) > window_sec:
            q.popleft()
        return len(q)

    def get_syn_count(self, src_ip: str, window_sec: float) -> int:
        now = time.time()
        q = self._syn_timestamps[src_ip]
        while q and (now - q[0]) > window_sec:
            q.popleft()
        return len(q)

    def get_icmp_count(self, src_ip: str, window_sec: float) -> int:
        now = time.time()
        q = self._icmp_timestamps[src_ip]
        while q and (now - q[0]) > window_sec:
            q.popleft()
        return len(q)

    def get_dns_count(self, src_ip: str, window_sec: float) -> int:
        now = time.time()
        q = self._dns_timestamps[src_ip]
        while q and (now - q[0]) > window_sec:
            q.popleft()
        return len(q)

    def get_distinct_ports_count(self, src_ip: str, window_sec: float) -> int:
        now = time.time()
        q = self._port_scan_events[src_ip]
        while q and (now - q[0][0]) > window_sec:
            q.popleft()
        return len(set(e[1] for e in q))

    def get_slowloris_count(self, src_ip: str, window_sec: float) -> int:
        now = time.time()
        q = self._slowloris_events[src_ip]
        while q and (now - q[0]) > window_sec:
            q.popleft()
        return len(q)

    def get_botnet_unique_ips_count(self, window_sec: float) -> int:
        now = time.time()
        while self._botnet_src_timestamps and (now - self._botnet_src_timestamps[0][0]) > window_sec:
            self._botnet_src_timestamps.popleft()
        return len(set(e[1] for e in self._botnet_src_timestamps))

    def cleanup_old(self, now: float | None = None) -> None:
        if now is None:
            now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        rate_sec = 2.0
        for key in list(self._rate_timestamps.keys()):
            q = self._rate_timestamps[key]
            while q and (now - q[0]) > rate_sec:
                q.popleft()
            if not q:
                del self._rate_timestamps[key]
        syn_win = self._config["SYN_FLOOD_WINDOW_SEC"]
        for key in list(self._syn_timestamps.keys()):
            q = self._syn_timestamps[key]
            while q and (now - q[0]) > syn_win:
                q.popleft()
            if not q:
                del self._syn_timestamps[key]
        icmp_win = self._config["ICMP_FLOOD_WINDOW_SEC"]
        for key in list(self._icmp_timestamps.keys()):
            q = self._icmp_timestamps[key]
            while q and (now - q[0]) > icmp_win:
                q.popleft()
            if not q:
                del self._icmp_timestamps[key]
        dns_win = self._config.get("DNS_FLOOD_WINDOW_SEC", 1.0)
        for key in list(self._dns_timestamps.keys()):
            q = self._dns_timestamps[key]
            while q and (now - q[0]) > dns_win:
                q.popleft()
            if not q:
                del self._dns_timestamps[key]
        port_win = self._config["PORT_SCAN_WINDOW_SEC"]
        for key in list(self._port_scan_events.keys()):
            q = self._port_scan_events[key]
            while q and (now - q[0][0]) > port_win:
                q.popleft()
            if not q:
                del self._port_scan_events[key]
        slow_win = self._config.get("SLOWLORIS_WINDOW_SEC", 30.0)
        for key in list(self._slowloris_events.keys()):
            q = self._slowloris_events[key]
            while q and (now - q[0]) > slow_win:
                q.popleft()
            if not q:
                del self._slowloris_events[key]
        bot_win = self._config.get("BOTNET_WINDOW_SEC", 10.0)
        while self._botnet_src_timestamps and (now - self._botnet_src_timestamps[0][0]) > bot_win:
            self._botnet_src_timestamps.popleft()

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_packets": self._total_packets,
            "allowed_count": self._allowed_count,
            "blocked_count": self._blocked_count,
            "alert_count": self._alert_count,
        }

    def get_blocked_ips(self) -> set[str]:
        return set(self._blocked_ips)


# Singleton used by detector and sniffer
_state: FirewallState | None = None


def get_firewall_state() -> FirewallState:
    global _state
    if _state is None:
        _state = FirewallState()
    return _state
