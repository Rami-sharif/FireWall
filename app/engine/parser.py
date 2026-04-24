"""
Packet parsing: convert Scapy packet to structured dict.
"""

from scapy.all import IP, TCP, UDP, ICMP, Raw

from app.utils.constants import (
    DEFAULT_PAYLOAD_SUMMARY_LEN,
    PROTOCOL_ICMP,
    PROTOCOL_OTHER,
    PROTOCOL_TCP,
    PROTOCOL_UDP,
)
from app.utils.helpers import payload_safe_summary


def parse_packet(packet) -> dict:
    """
    Extract structured fields from a Scapy packet.
    Returns dict with: src_ip, dst_ip, protocol, src_port, dst_port, length, tcp_flags, payload_summary.
    Handles missing layers gracefully.
    """
    result = {
        "src_ip": None,
        "dst_ip": None,
        "protocol": PROTOCOL_OTHER,
        "src_port": None,
        "dst_port": None,
        "length": None,
        "tcp_flags": None,
        "payload_summary": "",
    }

    if not packet:
        return result

    # IP layer
    if packet.haslayer(IP):
        ip = packet[IP]
        result["src_ip"] = ip.src
        result["dst_ip"] = ip.dst
        result["length"] = len(packet)

    # TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        result["protocol"] = PROTOCOL_TCP
        result["src_port"] = tcp.sport
        result["dst_port"] = tcp.dport
        flags = []
        if tcp.flags.S:
            flags.append("SYN")
        if tcp.flags.A:
            flags.append("ACK")
        if tcp.flags.F:
            flags.append("FIN")
        if tcp.flags.R:
            flags.append("RST")
        if tcp.flags.P:
            flags.append("PSH")
        result["tcp_flags"] = ",".join(flags) if flags else None
        if packet.haslayer(Raw):
            result["payload_summary"] = payload_safe_summary(
                bytes(packet[Raw].load),
                max_len=DEFAULT_PAYLOAD_SUMMARY_LEN,
            )
        return result

    # UDP
    if packet.haslayer(UDP):
        udp = packet[UDP]
        result["protocol"] = PROTOCOL_UDP
        result["src_port"] = udp.sport
        result["dst_port"] = udp.dport
        if packet.haslayer(Raw):
            result["payload_summary"] = payload_safe_summary(
                bytes(packet[Raw].load),
                max_len=DEFAULT_PAYLOAD_SUMMARY_LEN,
            )
        return result

    # ICMP
    if packet.haslayer(ICMP):
        result["protocol"] = PROTOCOL_ICMP
        if packet.haslayer(Raw):
            result["payload_summary"] = payload_safe_summary(
                bytes(packet[Raw].load),
                max_len=DEFAULT_PAYLOAD_SUMMARY_LEN,
            )
        return result

    return result
