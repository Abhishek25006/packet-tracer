"""
NetPulse capture engine — extended with protocol classification and
TCP handshake reconstruction per Project 4 spec.

Only run this on an interface/network you own or are authorized to
monitor (home lab, isolated VM network, or a lab network with
explicit permission).
"""

import time
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP

from protocols.http_analyzer import analyze_http
from protocols.dns_analyzer import analyze_dns, DNSTracker
from protocols.tls_analyzer import analyze_tls
from protocols.icmp_analyzer import analyze_icmp, PingSweepDetector
from analyzers.tcp_handshake import TCPHandshakeTracker


class PacketCapture:

    def __init__(self, on_packet=None, on_summary=None):
        """
        on_packet: optional callable(packet_info: dict) invoked for every
                   classified packet — used to stream live events out
                   over a WebSocket.
        on_summary: optional callable(summary: dict) invoked whenever the
                   summary report is (re)generated.
        """
        self.running = False
        self.packet_count = 0
        self.on_packet = on_packet
        self.on_summary = on_summary

        # Per-protocol counters for the summary report
        self.protocol_counts = {
            "TCP": 0, "UDP": 0, "ICMP": 0,
            "HTTP": 0, "DNS": 0, "TLS": 0, "OTHER": 0,
        }

        self.tcp_tracker = TCPHandshakeTracker()
        self.dns_tracker = DNSTracker()
        self.ping_sweep_detector = PingSweepDetector()

        self.http_events = []
        self.dns_events = []
        self.tls_events = []
        self.icmp_events = []

    def analyze_packet(self, packet):
        self.packet_count += 1
        now = time.time()

        packet_info = {
            "id": self.packet_count,
            "timestamp": datetime.now().isoformat(),
            "protocol": "UNKNOWN",
            "source": "N/A",
            "destination": "N/A",
            "source_port": None,
            "destination_port": None,
            "length": len(packet),
            "flags": None,
        }

        if IP in packet:
            packet_info["source"] = packet[IP].src
            packet_info["destination"] = packet[IP].dst

        # --- Base transport-layer classification ---
        if TCP in packet:
            packet_info["protocol"] = "TCP"
            packet_info["source_port"] = packet[TCP].sport
            packet_info["destination_port"] = packet[TCP].dport
            packet_info["flags"] = str(packet[TCP].flags)

            # TCP handshake tracking (SYN / SYN-ACK / ACK)
            self.tcp_tracker.process(packet, now)

            # Application-layer parsing on top of TCP
            analyze_http(packet, packet_info)
            analyze_tls(packet, packet_info)

        elif UDP in packet:
            packet_info["protocol"] = "UDP"
            packet_info["source_port"] = packet[UDP].sport
            packet_info["destination_port"] = packet[UDP].dport

            analyze_dns(packet, packet_info)
            if packet_info["protocol"] == "DNS" and IP in packet:
                self.dns_tracker.record(packet[IP].src, now)

        elif ICMP in packet:
            analyze_icmp(packet, packet_info)
            if IP in packet and packet[ICMP].type == 8:  # Echo Request
                self.ping_sweep_detector.record_echo_request(
                    packet[IP].src, packet[IP].dst, now
                )

        # --- Bucket into per-protocol event logs for the report ---
        proto = packet_info["protocol"]
        if proto == "HTTP":
            self.http_events.append(packet_info)
        elif proto == "DNS":
            self.dns_events.append(packet_info)
        elif proto == "TLS":
            self.tls_events.append(packet_info)
        elif proto == "ICMP":
            self.icmp_events.append(packet_info)

        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1

        return packet_info

    def packet_callback(self, packet):
        packet_info = self.analyze_packet(packet)

        if self.on_packet is not None:
            try:
                self.on_packet(packet_info)
            except Exception as e:
                print(f"[on_packet callback error] {e}")

        extra = ""
        if packet_info["protocol"] == "HTTP" and "http_method" in packet_info:
            extra = f" {packet_info['http_method']} {packet_info.get('http_host', '')}{packet_info.get('http_path', '')}"
        elif packet_info["protocol"] == "DNS" and "dns_query" in packet_info:
            extra = f" query={packet_info['dns_query']} ({packet_info.get('dns_qtype')})"
        elif packet_info["protocol"] == "TLS" and "sni" in packet_info:
            extra = f" SNI={packet_info['sni']}"

        print(
            f"[{packet_info['protocol']}] "
            f"{packet_info['source']} -> "
            f"{packet_info['destination']} "
            f"Length={packet_info['length']}{extra}"
        )

    def generate_summary(self):
        """Builds the per-protocol summary report described in the spec."""
        report = {
            "total_packets": self.packet_count,
            "protocol_counts": self.protocol_counts,
            "tcp_handshakes": self.tcp_tracker.summary(),
            "incomplete_handshakes": [
                r.to_dict() for r in self.tcp_tracker.incomplete_handshakes()
            ],
            "dns_query_volume": self.dns_tracker.summary(),
            "dns_anomalies": [
                ip for ip in self.dns_tracker.summary()
                if self.dns_tracker.is_anomalous(ip)
            ],
            "ping_sweep_candidates": [
                ip for ip in self.ping_sweep_detector.summary()
                if self.ping_sweep_detector.is_sweep(ip)
            ],
            "tls_hosts_seen": sorted({
                e["sni"] for e in self.tls_events if "sni" in e
            }),
            "http_requests": len([e for e in self.http_events if e.get("http_type") == "request"]),
        }
        return report

    def print_summary(self):
        report = self.generate_summary()
        if self.on_summary is not None:
            try:
                self.on_summary(report)
            except Exception as e:
                print(f"[on_summary callback error] {e}")
        print("\n==================== SUMMARY ====================")
        print(f"Total packets captured : {report['total_packets']}")
        print(f"Protocol breakdown     : {report['protocol_counts']}")
        print(f"TCP handshakes         : {report['tcp_handshakes']}")
        if report["incomplete_handshakes"]:
            print(f"Incomplete handshakes  : {len(report['incomplete_handshakes'])} "
                  f"(possible SYN scan indicators)")
        if report["dns_anomalies"]:
            print(f"DNS anomalies          : {report['dns_anomalies']}")
        if report["ping_sweep_candidates"]:
            print(f"Ping sweep candidates  : {report['ping_sweep_candidates']}")
        if report["tls_hosts_seen"]:
            print(f"TLS hosts (via SNI)    : {report['tls_hosts_seen']}")
        print("==================================================\n")
        return report

    def start(self, iface=None, bpf_filter=None, count=0):
        """
        iface: network interface to sniff on (None = scapy default)
        bpf_filter: optional BPF filter string, e.g. "tcp or udp or icmp"
        count: number of packets to capture (0 = unlimited, stop with Ctrl+C)
        """
        if self.running:
            return

        self.running = True
        self.packet_count = 0

        print("====================================")
        print("      NETPULSE PACKET CAPTURE")
        print("====================================")
        print("Only run on networks/interfaces you own or are authorized to monitor.")
        print("Capture started...")
        print("Press CTRL+C to stop.\n")

        try:
            sniff(
                prn=self.packet_callback,
                store=False,
                iface=iface,
                filter=bpf_filter,
                count=count,
                stop_filter=lambda pkt: not self.running,
            )
        except KeyboardInterrupt:
            print("\nCapture stopped.")
        finally:
            self.running = False
            self.print_summary()

    def stop(self):
        """Signals the sniff loop (via stop_filter) to exit after the
        next packet. Call from a control endpoint to stop a background
        capture thread gracefully."""
        self.running = False

    def analyze_pcap(self, pcap_path):
        """Offline analysis mode — reads a .pcap file instead of live capture."""
        from scapy.all import rdpcap

        print(f"Loading {pcap_path} ...")
        packets = rdpcap(pcap_path)
        print(f"Loaded {len(packets)} packets. Analyzing...\n")

        for packet in packets:
            self.packet_callback(packet)

        return self.print_summary()


if __name__ == "__main__":
    import sys

    capture = PacketCapture()

    if len(sys.argv) > 1 and sys.argv[1].endswith(".pcap"):
        capture.analyze_pcap(sys.argv[1])
    else:
        capture.start()