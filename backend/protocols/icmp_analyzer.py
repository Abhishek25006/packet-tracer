"""
ICMP analyzer.

Spec requirement: "ICMP traffic summary (ping sweeps, unreachable messages)"
"""

from scapy.all import ICMP

ICMP_TYPE_MAP = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
}

ICMP_UNREACHABLE_CODES = {
    0: "Network Unreachable",
    1: "Host Unreachable",
    2: "Protocol Unreachable",
    3: "Port Unreachable",
    4: "Fragmentation Needed",
}


def analyze_icmp(packet, packet_info):
    if ICMP not in packet:
        return packet_info

    icmp = packet[ICMP]
    packet_info["protocol"] = "ICMP"
    packet_info["icmp_type"] = ICMP_TYPE_MAP.get(icmp.type, f"Type {icmp.type}")

    if icmp.type == 3:
        packet_info["icmp_detail"] = ICMP_UNREACHABLE_CODES.get(icmp.code, f"Code {icmp.code}")

    return packet_info


class PingSweepDetector:
    """
    Flags a source IP as running a ping sweep if it sends echo requests
    to more than `distinct_target_threshold` distinct destinations
    within `window_seconds`.
    """

    def __init__(self, window_seconds=30, distinct_target_threshold=10):
        self.window_seconds = window_seconds
        self.distinct_target_threshold = distinct_target_threshold
        self._log = {}  # src_ip -> list of (timestamp, dst_ip)

    def record_echo_request(self, src_ip, dst_ip, timestamp):
        entries = self._log.setdefault(src_ip, [])
        entries.append((timestamp, dst_ip))
        cutoff = timestamp - self.window_seconds
        self._log[src_ip] = [(t, d) for t, d in entries if t >= cutoff]

    def is_sweep(self, src_ip):
        entries = self._log.get(src_ip, [])
        distinct_targets = {d for _, d in entries}
        return len(distinct_targets) > self.distinct_target_threshold

    def summary(self):
        return {
            ip: len({d for _, d in entries})
            for ip, entries in self._log.items()
        }