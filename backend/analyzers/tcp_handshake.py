"""
TCP three-way handshake tracker.

Spec requirements:
  - "TCP three-way handshake visualization (SYN, SYN-ACK, ACK sequence and timing)"
  - "Reconstruct and validate TCP handshake sequences"

Approach: key connections by the 4-tuple (client_ip, client_port,
server_ip, server_port), using the *client's* perspective (the side
that sent the initial SYN) as the canonical key. Track which of the
three expected packets have been seen and the timestamp of each, so
we can compute SYN->SYN-ACK and SYN-ACK->ACK latency.
"""

from dataclasses import dataclass, field
from typing import Optional
from scapy.all import TCP, IP


@dataclass
class HandshakeRecord:
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    syn_time: Optional[float] = None
    synack_time: Optional[float] = None
    ack_time: Optional[float] = None
    complete: bool = False

    @property
    def conn_key(self):
        return (self.client_ip, self.client_port, self.server_ip, self.server_port)

    def syn_to_synack_ms(self):
        if self.syn_time is not None and self.synack_time is not None:
            return round((self.synack_time - self.syn_time) * 1000, 3)
        return None

    def synack_to_ack_ms(self):
        if self.synack_time is not None and self.ack_time is not None:
            return round((self.ack_time - self.synack_time) * 1000, 3)
        return None

    def total_handshake_ms(self):
        if self.syn_time is not None and self.ack_time is not None:
            return round((self.ack_time - self.syn_time) * 1000, 3)
        return None

    def to_dict(self):
        return {
            "client": f"{self.client_ip}:{self.client_port}",
            "server": f"{self.server_ip}:{self.server_port}",
            "syn_seen": self.syn_time is not None,
            "synack_seen": self.synack_time is not None,
            "ack_seen": self.ack_time is not None,
            "complete": self.complete,
            "syn_to_synack_ms": self.syn_to_synack_ms(),
            "synack_to_ack_ms": self.synack_to_ack_ms(),
            "total_handshake_ms": self.total_handshake_ms(),
        }


class TCPHandshakeTracker:
    def __init__(self):
        # keyed by (client_ip, client_port, server_ip, server_port)
        self._connections: dict[tuple, HandshakeRecord] = {}

    def process(self, packet, timestamp):
        """Feed a packet in; updates internal state. Returns the
        HandshakeRecord touched by this packet, if any."""
        if IP not in packet or TCP not in packet:
            return None

        ip = packet[IP]
        tcp = packet[TCP]
        flags = tcp.flags

        is_syn = flags == "S"
        is_synack = flags == "SA"
        is_ack = flags == "A"

        if is_syn:
            key = (ip.src, tcp.sport, ip.dst, tcp.dport)
            record = self._connections.get(key) or HandshakeRecord(
                client_ip=ip.src, client_port=tcp.sport,
                server_ip=ip.dst, server_port=tcp.dport,
            )
            record.syn_time = timestamp
            self._connections[key] = record
            return record

        if is_synack:
            # SYN-ACK is sent server->client, so flip to find the client's key
            key = (ip.dst, tcp.dport, ip.src, tcp.sport)
            record = self._connections.get(key)
            if record is None:
                return None  # SYN-ACK with no observed SYN (mid-capture start)
            record.synack_time = timestamp
            return record

        if is_ack:
            key = (ip.src, tcp.sport, ip.dst, tcp.dport)
            record = self._connections.get(key)
            if record is None:
                return None
            # Only count this ACK as the handshake-closing ACK if SYN-ACK
            # was already seen and we haven't completed yet.
            if record.synack_time is not None and not record.complete:
                record.ack_time = timestamp
                record.complete = True
                return record

        return None

    def incomplete_handshakes(self):
        """Connections that never reached a full SYN/SYN-ACK/ACK —
        useful for spotting SYN scans."""
        return [r for r in self._connections.values() if not r.complete]

    def all_handshakes(self):
        return list(self._connections.values())

    def summary(self):
        records = self.all_handshakes()
        complete = [r for r in records if r.complete]
        return {
            "total_connections_observed": len(records),
            "completed_handshakes": len(complete),
            "incomplete_handshakes": len(records) - len(complete),
            "avg_total_handshake_ms": (
                round(sum(r.total_handshake_ms() for r in complete) / len(complete), 3)
                if complete else None
            ),
        }