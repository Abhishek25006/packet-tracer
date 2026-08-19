"""
DNS analyzer — extracts query/response info from DNS packets.

Spec requirement: "DNS query/response extraction (domain, record type, resolved IP)"
"""

from scapy.all import DNS, DNSQR, DNSRR, IP

# Common DNS record types (add more as needed)
QTYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


def analyze_dns(packet, packet_info):
    """
    Mutates packet_info in place if the packet carries a DNS layer.
    Returns packet_info regardless (for chaining).
    """
    if DNS not in packet:
        return packet_info

    dns = packet[DNS]
    packet_info["protocol"] = "DNS"

    # qr == 0 -> query, qr == 1 -> response
    is_response = dns.qr == 1
    packet_info["dns_type"] = "response" if is_response else "query"

    # Query name / record type (from the question section)
    if dns.qdcount > 0 and dns.qd is not None:
        qname = dns.qd.qname.decode(errors="replace").rstrip(".")
        qtype = QTYPE_MAP.get(dns.qd.qtype, str(dns.qd.qtype))
        packet_info["dns_query"] = qname
        packet_info["dns_qtype"] = qtype

    # Resolved answers (only present in responses)
    if is_response and dns.ancount > 0:
        answers = []
        rr = dns.an
        for _ in range(dns.ancount):
            if rr is None:
                break
            rtype = QTYPE_MAP.get(rr.type, str(rr.type))
            try:
                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode(errors="replace")
                else:
                    rdata = str(rdata)
            except Exception:
                rdata = "N/A"
            answers.append({"type": rtype, "value": rdata})
            rr = rr.payload if hasattr(rr, "payload") and isinstance(rr.payload, DNSRR) else None
        packet_info["dns_answers"] = answers

    return packet_info


class DNSTracker:
    """
    Tracks DNS query volume per source IP to support anomaly detection
    (e.g. unusually high query rate = possible tunneling or recon activity).
    """

    def __init__(self, window_seconds=60, threshold=50):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self._log = {}  # src_ip -> list of timestamps

    def record(self, src_ip, timestamp):
        self._log.setdefault(src_ip, []).append(timestamp)
        # prune old entries
        cutoff = timestamp - self.window_seconds
        self._log[src_ip] = [t for t in self._log[src_ip] if t >= cutoff]

    def is_anomalous(self, src_ip):
        return len(self._log.get(src_ip, [])) > self.threshold

    def summary(self):
        return {ip: len(times) for ip, times in self._log.items()}