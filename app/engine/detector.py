"""
Detection of suspicious behavior: rate, SYN flood, ICMP flood, port scan, payload pattern.
Maintains in-memory state per source IP; returns list of detection tags.
"""

import time
from collections import defaultdict, deque
from typing import Any

from app.utils.config import get_config
from app.utils.constants import (
    DETECTION_ICMP_FLOOD,
    DETECTION_PORT_SCAN,
    DETECTION_RATE_LIMIT,
    DETECTION_SUSPICIOUS_PAYLOAD,
    DETECTION_SYN_FLOOD,
    PROTOCOL_ICMP,
    PROTOCOL_TCP,
)


class Detector:
    def __init__(self):
        self._config = get_config()
        # Per-source IP: deque of (timestamp,) for rate
        self._rate_timestamps: dict[str, deque[float]] = defaultdict(deque)
        # SYN per src: deque of timestamps
        self._syn_timestamps: dict[str, deque[float]] = defaultdict(deque)
        # ICMP per src: deque of timestamps
        self._icmp_timestamps: dict[str, deque[float]] = defaultdict(deque)
        # Port scan: per src, set of (dst_port,) in window
        self._port_scan_events: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._window_cleanup_interval = 60.0
        self._last_cleanup = time.time()

    def _cleanup_old(self, now: float) -> None:
        if now - self._last_cleanup < self._window_cleanup_interval:
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
        port_win = self._config["PORT_SCAN_WINDOW_SEC"]
        for key in list(self._port_scan_events.keys()):
            q = self._port_scan_events[key]
            while q and (now - q[0][0]) > port_win:
                q.popleft()
            if not q:
                del self._port_scan_events[key]

    def detect(self, parsed: dict[str, Any]) -> list[str]:
        """
        Return list of detection tags for this packet (e.g. rate_limit, syn_flood, ...).
        """
        tags = []
        now = time.time()
        self._cleanup_old(now)

        src_ip = parsed.get("src_ip")
        if not src_ip:
            return tags

        # Rate limit (packets per second)
        rate_threshold = self._config["RATE_THRESHOLD"]
        rate_window = 1.0
        q = self._rate_timestamps[src_ip]
        while q and (now - q[0]) > rate_window:
            q.popleft()
        q.append(now)
        if len(q) > rate_threshold:
            tags.append(DETECTION_RATE_LIMIT)

        # SYN flood (many SYN in window)
        if parsed.get("protocol") == PROTOCOL_TCP and parsed.get("tcp_flags") and "SYN" in (parsed.get("tcp_flags") or ""):
            syn_win = self._config["SYN_FLOOD_WINDOW_SEC"]
            syn_thresh = self._config["SYN_FLOOD_THRESHOLD"]
            sq = self._syn_timestamps[src_ip]
            while sq and (now - sq[0]) > syn_win:
                sq.popleft()
            sq.append(now)
            if len(sq) >= syn_thresh:
                tags.append(DETECTION_SYN_FLOOD)

        # ICMP flood
        if parsed.get("protocol") == PROTOCOL_ICMP:
            icmp_win = self._config["ICMP_FLOOD_WINDOW_SEC"]
            icmp_thresh = self._config["ICMP_FLOOD_THRESHOLD"]
            iq = self._icmp_timestamps[src_ip]
            while iq and (now - iq[0]) > icmp_win:
                iq.popleft()
            iq.append(now)
            if len(iq) >= icmp_thresh:
                tags.append(DETECTION_ICMP_FLOOD)

        # Port scan: many distinct dst ports in window
        dst_port = parsed.get("dst_port")
        if dst_port is not None:
            port_win = self._config["PORT_SCAN_WINDOW_SEC"]
            port_thresh = self._config["PORT_SCAN_THRESHOLD"]
            pq = self._port_scan_events[src_ip]
            while pq and (now - pq[0][0]) > port_win:
                pq.popleft()
            pq.append((now, dst_port))
            distinct = len(set(e[1] for e in pq))
            if distinct >= port_thresh:
                tags.append(DETECTION_PORT_SCAN)

        # Suspicious payload: keyword match (e.g. Nimda)
        payload = (parsed.get("payload_summary") or "").upper()
        if "GET /SCRIPTS/ROOT.EXE" in payload or "ROOT.EXE" in payload:
            tags.append(DETECTION_SUSPICIOUS_PAYLOAD)

        return tags
