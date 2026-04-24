"""
Packet simulation: generate normal traffic, ICMP flood, SYN flood, suspicious payload, repeated connections.
For demos and testing without real attacks.

Two operating modes:
  - Network mode (default): uses Scapy send() — requires raw-socket privileges (root on Linux).
  - Direct mode (--direct / direct=True): skips send() entirely and injects crafted Scapy packet
    objects straight into the processing pipeline (parse → detect → rule_engine → log/alert).
    Works without any elevated privileges and is the correct mode for sandboxed / CI environments.
"""

import time
from typing import Optional

from scapy.all import IP, TCP, ICMP, Raw, send

from app.utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Direct-injection helper
# ---------------------------------------------------------------------------

def _inject(pkt) -> dict:
    """
    Push a Scapy packet directly through the processing pipeline without
    sending it over the network.  Returns the decision dict.
    """
    from app.engine.parser import parse_packet
    from app.engine.detector import Detector
    from app.engine.rule_engine import evaluate
    from app.engine.enforcer import apply_block
    from app.services.log_service import add_log
    from app.services.alert_service import create_alert
    from app.utils.constants import ACTION_BLOCK, ACTION_ALERT, SEVERITY_HIGH, SEVERITY_MEDIUM

    # Use a module-level Detector so state accumulates across calls
    # (needed for flood / port-scan detection in multi-packet scenarios).
    if not hasattr(_inject, "_detector"):
        _inject._detector = Detector()

    parsed = parse_packet(pkt)
    detection_tags = _inject._detector.detect(parsed)
    decision = evaluate(parsed, detection_tags)
    action = decision.get("action", "ALLOW")
    rule_id = decision.get("rule_id")
    reason = decision.get("reason", "")

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

    if action in (ACTION_BLOCK, ACTION_ALERT) or detection_tags:
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

    if action == ACTION_BLOCK:
        src_ip = parsed.get("src_ip")
        if src_ip:
            apply_block(src_ip)

    return decision


def _send_or_inject(pkt, direct: bool, delay: float) -> None:
    """Send a packet over the network or inject it directly into the pipeline."""
    if direct:
        _inject(pkt)
    else:
        send(pkt, verbose=False)
    if delay > 0:
        time.sleep(delay)


# ---------------------------------------------------------------------------
# Scenario functions
# ---------------------------------------------------------------------------

def send_normal_traffic(
    target_ip: str,
    count: int = 10,
    source_ip: str = "192.168.1.100",
    delay: float = 0.1,
    direct: bool = False,
) -> None:
    """Send normal-looking TCP packets to target (e.g. port 80)."""
    for i in range(count):
        pkt = (
            IP(src=source_ip, dst=target_ip)
            / TCP(sport=30000 + i, dport=80, flags="S")
        )
        _send_or_inject(pkt, direct, delay)
    logger.info("Simulator: sent %d normal packets to %s", count, target_ip)


def send_icmp_flood(
    target_ip: str,
    count: int = 50,
    source_ip: str = "192.168.1.101",
    delay: float = 0.0,
    direct: bool = False,
) -> None:
    """Simulate ICMP flood (many ICMP requests)."""
    for i in range(count):
        pkt = IP(src=source_ip, dst=target_ip) / ICMP()
        _send_or_inject(pkt, direct, delay)
    logger.info("Simulator: sent %d ICMP packets to %s", count, target_ip)


def send_syn_flood(
    target_ip: str,
    port: int = 80,
    count: int = 50,
    source_ip: str = "192.168.1.102",
    delay: float = 0.0,
    direct: bool = False,
) -> None:
    """Simulate SYN flood (many SYN packets to same port)."""
    for i in range(count):
        pkt = (
            IP(src=source_ip, dst=target_ip)
            / TCP(sport=40000 + i, dport=port, flags="S")
        )
        _send_or_inject(pkt, direct, delay)
    logger.info("Simulator: sent %d SYN packets to %s:%s", count, target_ip, port)


def send_suspicious_payload(
    target_ip: str,
    port: int = 80,
    source_ip: str = "192.168.1.103",
    source_port: int = 12345,
    direct: bool = False,
) -> None:
    """Send a packet with Nimda-like payload (GET /scripts/root.exe)."""
    payload = "GET /scripts/root.exe HTTP/1.0\r\nHost: example.com\r\n\r\n"
    pkt = (
        IP(src=source_ip, dst=target_ip)
        / TCP(sport=source_port, dport=port)
        / Raw(load=payload)
    )
    _send_or_inject(pkt, direct, 0.0)
    logger.info("Simulator: sent suspicious payload packet to %s:%s", target_ip, port)


def send_repeated_connections(
    target_ip: str,
    port: int = 80,
    count: int = 30,
    source_ip: str = "192.168.1.104",
    delay: float = 0.05,
    direct: bool = False,
) -> None:
    """Repeated connection attempts (SYNs) from same source to same port (rate-like)."""
    for i in range(count):
        pkt = (
            IP(src=source_ip, dst=target_ip)
            / TCP(sport=50000 + i, dport=port, flags="S")
        )
        _send_or_inject(pkt, direct, delay)
    logger.info("Simulator: sent %d repeated connection packets to %s:%s", count, target_ip, port)


def run_scenario(
    scenario: str,
    target_ip: str = "127.0.0.1",
    count: Optional[int] = None,
    port: int = 80,
    direct: bool = False,
) -> None:
    """Run a named scenario. Used by CLI or tests."""
    if scenario == "normal":
        send_normal_traffic(target_ip, count=count or 10, direct=direct)
    elif scenario == "icmp_flood":
        send_icmp_flood(target_ip, count=count or 50, direct=direct)
    elif scenario == "syn_flood":
        send_syn_flood(target_ip, port=port, count=count or 50, direct=direct)
    elif scenario == "suspicious_payload":
        send_suspicious_payload(target_ip, port=port, direct=direct)
    elif scenario == "repeated":
        send_repeated_connections(target_ip, port=port, count=count or 30, direct=direct)
    else:
        logger.warning("Unknown scenario: %s", scenario)


if __name__ == "__main__":
    import argparse
    import os
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

    p = argparse.ArgumentParser(description="Smart Firewall packet simulator")
    p.add_argument("--target", default="127.0.0.1", help="Target IP")
    p.add_argument(
        "--scenario",
        default="normal",
        choices=["normal", "icmp_flood", "syn_flood", "suspicious_payload", "repeated"],
    )
    p.add_argument("--count", type=int, default=None)
    p.add_argument("--port", type=int, default=80)
    p.add_argument(
        "--direct",
        action="store_true",
        help=(
            "Inject packets directly into the detection pipeline instead of "
            "sending them over the network.  Does not require root privileges."
        ),
    )
    args = p.parse_args()

    if args.direct:
        # Ensure the database is initialised before processing any packets.
        from app.db.database import init_db
        init_db()
        print(f"[simulator] direct mode — injecting into pipeline (no network)")
    else:
        print(f"[simulator] network mode — sending raw packets (requires root on Linux)")

    run_scenario(
        args.scenario,
        target_ip=args.target,
        count=args.count,
        port=args.port,
        direct=args.direct,
    )

    print(f"[simulator] scenario '{args.scenario}' complete.")
