"""
TLS/HTTPS handshake analyzer.

Spec requirement: "TLS/HTTPS handshake detection (SNI extraction, cipher
summary — without decrypting payload)"

We do NOT decrypt anything. We only parse the plaintext parts of the
TLS handshake that are visible on the wire before encryption kicks in:
  - ClientHello: SNI (server name), offered cipher suites, TLS version
  - ServerHello: chosen cipher suite, TLS version

This is done by manually walking the TLS record/handshake structure,
since scapy does not parse TLS by default (avoids depending on the
scapy-tls extra, which is fiddly to install).
"""

from scapy.all import TCP, Raw

TLS_CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
HANDSHAKE_TYPE_SERVER_HELLO = 0x02
EXTENSION_TYPE_SNI = 0x0000

TLS_VERSION_MAP = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# A small subset of common cipher suite IDs for readability.
CIPHER_SUITE_MAP = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE_ECDSA_AES_128_GCM_SHA256",
    0xC02C: "ECDHE_ECDSA_AES_256_GCM_SHA384",
    0xC02F: "ECDHE_RSA_AES_128_GCM_SHA256",
    0xC030: "ECDHE_RSA_AES_256_GCM_SHA384",
}


def _parse_client_hello(hs_body):
    """hs_body: bytes of the handshake message body, starting after the
    4-byte handshake header (type + length)."""
    info = {}
    try:
        # ClientHello structure:
        # version(2) + random(32) + session_id_len(1) + session_id(var)
        version = int.from_bytes(hs_body[0:2], "big")
        info["tls_version"] = TLS_VERSION_MAP.get(version, hex(version))

        offset = 2 + 32
        session_id_len = hs_body[offset]
        offset += 1 + session_id_len

        cipher_suites_len = int.from_bytes(hs_body[offset:offset + 2], "big")
        offset += 2
        cipher_bytes = hs_body[offset:offset + cipher_suites_len]
        offset += cipher_suites_len
        ciphers = [
            int.from_bytes(cipher_bytes[i:i + 2], "big")
            for i in range(0, len(cipher_bytes), 2)
        ]
        info["offered_ciphers"] = [
            CIPHER_SUITE_MAP.get(c, hex(c)) for c in ciphers[:5]  # cap for readability
        ]

        compression_len = hs_body[offset]
        offset += 1 + compression_len

        if offset + 2 > len(hs_body):
            return info  # no extensions present

        extensions_len = int.from_bytes(hs_body[offset:offset + 2], "big")
        offset += 2
        ext_end = offset + extensions_len

        while offset + 4 <= ext_end:
            ext_type = int.from_bytes(hs_body[offset:offset + 2], "big")
            ext_len = int.from_bytes(hs_body[offset + 2:offset + 4], "big")
            ext_data = hs_body[offset + 4:offset + 4 + ext_len]

            if ext_type == EXTENSION_TYPE_SNI and len(ext_data) > 5:
                # server_name_list: list_len(2) + type(1) + name_len(2) + name
                name_len = int.from_bytes(ext_data[3:5], "big")
                server_name = ext_data[5:5 + name_len].decode(errors="replace")
                info["sni"] = server_name

            offset += 4 + ext_len

    except (IndexError, ValueError):
        pass

    return info


def _parse_server_hello(hs_body):
    info = {}
    try:
        version = int.from_bytes(hs_body[0:2], "big")
        info["tls_version"] = TLS_VERSION_MAP.get(version, hex(version))

        offset = 2 + 32
        session_id_len = hs_body[offset]
        offset += 1 + session_id_len

        cipher = int.from_bytes(hs_body[offset:offset + 2], "big")
        info["chosen_cipher"] = CIPHER_SUITE_MAP.get(cipher, hex(cipher))
    except (IndexError, ValueError):
        pass
    return info


def analyze_tls(packet, packet_info):
    if TCP not in packet or Raw not in packet:
        return packet_info

    payload = bytes(packet[Raw].load)
    if len(payload) < 6 or payload[0] != TLS_CONTENT_TYPE_HANDSHAKE:
        return packet_info

    handshake_type = payload[5]
    hs_body = payload[9:]  # skip 5-byte record header + 4-byte handshake header

    if handshake_type == HANDSHAKE_TYPE_CLIENT_HELLO:
        details = _parse_client_hello(hs_body)
        packet_info["protocol"] = "TLS"
        packet_info["tls_type"] = "ClientHello"
        packet_info.update(details)

    elif handshake_type == HANDSHAKE_TYPE_SERVER_HELLO:
        details = _parse_server_hello(hs_body)
        packet_info["protocol"] = "TLS"
        packet_info["tls_type"] = "ServerHello"
        packet_info.update(details)

    return packet_info