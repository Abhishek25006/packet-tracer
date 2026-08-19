"""
HTTP analyzer — parses plaintext HTTP requests/responses from TCP payloads.

Spec requirement: "HTTP request/response parsing (method, host, status)"

Note: this only sees plaintext HTTP (port 80 or unencrypted traffic).
HTTPS traffic is handled separately in tls_analyzer.py via SNI, since
payload is encrypted and we do NOT attempt to decrypt it.
"""

from scapy.all import TCP, Raw

HTTP_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH")


def analyze_http(packet, packet_info):
    if TCP not in packet or Raw not in packet:
        return packet_info

    payload = bytes(packet[Raw].load)

    # --- Request ---
    if payload.startswith(HTTP_METHODS):
        try:
            lines = payload.split(b"\r\n")
            request_line = lines[0].decode(errors="replace")
            method, path, _ = request_line.split(" ", 2)

            host = None
            for line in lines[1:]:
                if line.lower().startswith(b"host:"):
                    host = line.split(b":", 1)[1].strip().decode(errors="replace")
                    break

            packet_info["protocol"] = "HTTP"
            packet_info["http_type"] = "request"
            packet_info["http_method"] = method
            packet_info["http_path"] = path
            packet_info["http_host"] = host
        except (ValueError, IndexError):
            pass

    # --- Response ---
    elif payload.startswith(b"HTTP/"):
        try:
            lines = payload.split(b"\r\n")
            status_line = lines[0].decode(errors="replace")
            _, status_code, *reason = status_line.split(" ")

            packet_info["protocol"] = "HTTP"
            packet_info["http_type"] = "response"
            packet_info["http_status"] = int(status_code)
            packet_info["http_reason"] = " ".join(reason)
        except (ValueError, IndexError):
            pass

    return packet_info