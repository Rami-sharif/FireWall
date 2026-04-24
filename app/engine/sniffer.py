"""
Packet sniffer: capture packets, run parser -> detector -> rule_engine -> log/alert/stats -> enforcer.
Runs in a background thread; start/stop from API.
"""

import sys
import threading
import time
from typing import Optional

from scapy.all import sniff, IP, conf

from app.engine.parser import parse_packet
from app.engine.detector import Detector
from app.engine.rule_engine import evaluate
from app.engine.enforcer import apply_block, cleanup_all_blocks
from app.services.log_service import add_log
from app.services.alert_service import create_alert
from app.services.stats_service import get_stats_from_logs  # noqa: F401
from app.utils.config import get_config
from app.utils.constants import (
    ACTION_ALERT,
    ACTION_BLOCK,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


class FirewallSniffer:
    def __init__(self):
        self._config = get_config()
        self._detector = Detector()
        self._running = False
        self._thread: threading.Thread | None = None
        self._sniff_socket = None
        self.last_error: str | None = None

    def _packet_callback(self, packet) -> None:
        if not packet.haslayer(IP):
            return
        try:
            parsed = parse_packet(packet)
            detection_tags = self._detector.detect(parsed)
            decision = evaluate(parsed, detection_tags)
            action = decision.get("action", "ALLOW")
            rule_id = decision.get("rule_id")
            reason = decision.get("reason", "")

            # Log
            add_log(
                src_ip=parsed.get("src_ip"),
                dst_ip=parsed.get("dst_ip"),
                protocol=parsed.get("protocol"),
                src_port=parsed.get("src_port"),
                dst_port=parsed.get("dst_port"),
                length=parsed.get("length"),
                action=action,
                rule_id=rule_id,
                reason=reason,
            )

            # Alert on BLOCK or ALERT or detection tags
            if action == ACTION_BLOCK or action == ACTION_ALERT or detection_tags:
                severity = SEVERITY_HIGH if action == ACTION_BLOCK else SEVERITY_MEDIUM
                msg = f"Action={action}, reason={reason}"
                if detection_tags:
                    msg += ", detections=" + ",".join(detection_tags)
                create_alert(
                    message=msg,
                    severity=severity,
                    source_ip=parsed.get("src_ip"),
                    detection_type=detection_tags[0] if detection_tags else None,
                )

            # Enforce block only if action is BLOCK
            if action == ACTION_BLOCK:
                src_ip = parsed.get("src_ip")
                if src_ip:
                    apply_block(src_ip)

        except Exception as e:
            logger.exception("Error processing packet: %s", e)

    def start(self) -> bool:
        if self._running:
            return True
        self.last_error = None
        self._running = True
        self._thread = threading.Thread(target=self._run_sniff, daemon=True)
        self._thread.start()
        logger.info("Sniffer started")
        return True

    def _run_sniff(self) -> None:
        def stop_filter(_p):
            return not self._running

        try:
            if sys.platform == "win32":
                try:
                    sock = conf.L3socket()
                    sniff(
                        filter="ip",
                        prn=self._packet_callback,
                        opened_socket=sock,
                        stop_filter=stop_filter,
                    )
                except Exception as e:
                    logger.error("Sniffer L3 socket failed: %s", e)
                    self._running = False
            else:
                sniff(filter="ip", prn=self._packet_callback, stop_filter=stop_filter)
        except Exception as e:
            logger.exception("Sniffer error: %s", e)
            self.last_error = str(e)
        finally:
            self._running = False

    def stop(self) -> None:
        self._running = False
        cleanup_all_blocks()
        # Scapy sniff is blocking; we cannot interrupt it from outside without a custom socket.
        # So we rely on daemon thread and _running flag for future use (e.g. timeout sniff).
        logger.info("Sniffer stop requested (thread may still be in sniff until next packet)")

    @property
    def is_running(self) -> bool:
        return self._running


# Global instance for API control
_sniffer: FirewallSniffer | None = None


def get_sniffer() -> FirewallSniffer:
    global _sniffer
    if _sniffer is None:
        _sniffer = FirewallSniffer()
    return _sniffer
