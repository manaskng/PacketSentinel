#!/usr/bin/env python3
"""
generate_test_pcap.py — Generate a realistic 50,000-packet PCAP for DPI testing.

Creates:
  - test_large.pcap : 50K packet benchmark dataset
  - test_small.pcap : 500 packet quick-test dataset
  - ground_truth.json : expected SNI/app classification for accuracy testing

Traffic mix:
  - TLS Client Hellos with real SNIs (YouTube, Netflix, TikTok, etc.)
  - HTTP GET requests with Host headers
  - DNS queries
  - Multi-packet TCP flows (SYN -> SYN-ACK -> ACK -> Data)
  - Raw TCP data (continuation packets)
"""

import struct
import random
import json
import os
import sys
import socket
import time

# ---------------------------------------------------------------------------
# PCAP binary writer (no scapy dependency — pure stdlib)
# ---------------------------------------------------------------------------

PCAP_GLOBAL_HEADER = struct.pack(
    '<IHHiIII',
    0xa1b2c3d4,  # magic
    2, 4,        # version
    0,           # timezone
    0,           # sig figs
    65535,       # snaplen
    1            # Ethernet link type
)

def pcap_packet_header(ts_sec, ts_usec, data_len):
    return struct.pack('<IIII', ts_sec, ts_usec, data_len, data_len)

def mac_bytes(mac_str):
    return bytes(int(x, 16) for x in mac_str.split(':'))

def ip_to_bytes(ip_str):
    return socket.inet_aton(ip_str)

def checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

# ---------------------------------------------------------------------------
# Ethernet header
# ---------------------------------------------------------------------------
SRC_MAC = mac_bytes('00:11:22:33:44:55')
DST_MAC = mac_bytes('aa:bb:cc:dd:ee:ff')

def eth_header(ethertype=0x0800):
    return DST_MAC + SRC_MAC + struct.pack('>H', ethertype)

# ---------------------------------------------------------------------------
# IPv4 header
# ---------------------------------------------------------------------------
def ipv4_header(src_ip, dst_ip, protocol, payload_len, ttl=64):
    total_len = 20 + payload_len
    hdr = struct.pack('>BBHHHBBH4s4s',
        0x45,       # version=4, IHL=5
        0,          # DSCP
        total_len,
        random.randint(1, 65535),  # ID
        0,          # flags + fragment offset
        ttl,
        protocol,
        0,          # checksum (filled below)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip)
    )
    csum = checksum(hdr)
    return hdr[:10] + struct.pack('>H', csum) + hdr[12:]

# ---------------------------------------------------------------------------
# TCP header
# ---------------------------------------------------------------------------
def tcp_header(src_port, dst_port, seq, ack, flags, payload_len=0):
    # flags: 0x02=SYN, 0x10=ACK, 0x18=PSH+ACK, 0x01=FIN
    hdr = struct.pack('>HHIIBBHHH',
        src_port, dst_port,
        seq, ack,
        0x50,    # data offset = 5 (20 bytes), no options
        flags,
        65535,   # window
        0,       # checksum (not computed — DPI doesn't verify)
        0        # urgent
    )
    return hdr

# ---------------------------------------------------------------------------
# UDP header
# ---------------------------------------------------------------------------
def udp_header(src_port, dst_port, payload_len):
    length = 8 + payload_len
    return struct.pack('>HHHH', src_port, dst_port, length, 0)

# ---------------------------------------------------------------------------
# TLS Client Hello with SNI
# ---------------------------------------------------------------------------
def tls_client_hello(sni):
    sni_bytes = sni.encode('ascii')
    sni_len   = len(sni_bytes)

    # SNI extension
    sni_ext = (
        struct.pack('>H', sni_len + 3) +   # SNI list length
        struct.pack('>B', 0) +              # SNI type = hostname
        struct.pack('>H', sni_len) +        # hostname length
        sni_bytes
    )
    sni_extension = struct.pack('>HH', 0x0000, len(sni_ext)) + sni_ext

    # Other extensions (supported versions for TLS 1.3 appearance)
    supported_versions_ext = struct.pack('>HH', 0x002b, 8) + b'\x06\x03\x04\x03\x03\x03\x02'

    extensions = sni_extension + supported_versions_ext
    extensions_block = struct.pack('>H', len(extensions)) + extensions

    # Random (32 bytes)
    client_random = bytes(random.randint(0, 255) for _ in range(32))

    # Cipher suites
    cipher_suites = struct.pack('>HH', 0x1301, 0x1302)  # TLS 1.3 suites
    cipher_suites_block = struct.pack('>H', len(cipher_suites)) + cipher_suites

    # Compression methods
    compression = b'\x01\x00'  # length=1, no compression

    # Client Hello body
    client_hello_body = (
        b'\x03\x03' +          # client version TLS 1.2
        client_random +
        b'\x00' +              # session ID length = 0
        cipher_suites_block +
        compression +
        extensions_block
    )

    # Handshake header
    hs_len = len(client_hello_body)
    handshake = (
        b'\x01' +                                           # Client Hello
        struct.pack('>I', hs_len)[1:] +                     # 3-byte length
        client_hello_body
    )

    # TLS record header
    record = (
        b'\x16' +              # Content Type = Handshake
        b'\x03\x01' +          # Legacy version TLS 1.0
        struct.pack('>H', len(handshake)) +
        handshake
    )

    return record

# ---------------------------------------------------------------------------
# HTTP GET request with Host header
# ---------------------------------------------------------------------------
def http_get(host, path='/'):
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Mozilla/5.0 (DPI-Test/1.0)\r\n"
        f"Accept: */*\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    )
    return req.encode()

# ---------------------------------------------------------------------------
# DNS query for a domain
# ---------------------------------------------------------------------------
def dns_query(domain):
    # Transaction ID
    txid = random.randint(1, 65535)
    # Flags: standard query, recursion desired
    flags = 0x0100
    qdcount = 1

    header = struct.pack('>HHHHHH', txid, flags, qdcount, 0, 0, 0)

    # QNAME: labels separated by length bytes
    qname = b''
    for label in domain.rstrip('.').split('.'):
        lb = label.encode('ascii')
        qname += struct.pack('B', len(lb)) + lb
    qname += b'\x00'  # Root label

    question = qname + struct.pack('>HH', 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question

# ---------------------------------------------------------------------------
# Packet assembly helpers
# ---------------------------------------------------------------------------
def make_tcp_packet(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b''):
    tcp = tcp_header(src_port, dst_port, seq, ack, flags, len(payload))
    ip  = ipv4_header(src_ip, dst_ip, 6, len(tcp) + len(payload))
    eth = eth_header()
    return eth + ip + tcp + payload

def make_udp_packet(src_ip, dst_ip, src_port, dst_port, payload):
    udp = udp_header(src_port, dst_port, len(payload))
    ip  = ipv4_header(src_ip, dst_ip, 17, len(udp) + len(payload))
    eth = eth_header()
    return eth + ip + udp + payload

# ---------------------------------------------------------------------------
# Traffic definitions
# ---------------------------------------------------------------------------
APPS = [
    # (sni, app_name, dst_port, traffic_type)
    ('www.youtube.com',        'YouTube',   443, 'tls'),
    ('www.youtube.com',        'YouTube',   443, 'tls'),  # double weight
    ('www.netflix.com',        'Netflix',   443, 'tls'),
    ('www.tiktok.com',         'TikTok',    443, 'tls'),
    ('www.facebook.com',       'Facebook',  443, 'tls'),
    ('www.instagram.com',      'Instagram', 443, 'tls'),
    ('www.google.com',         'Google',    443, 'tls'),
    ('www.google.com',         'Google',    443, 'tls'),  # double weight
    ('www.github.com',         'GitHub',    443, 'tls'),
    ('discord.com',            'Discord',   443, 'tls'),
    ('www.reddit.com',         'Reddit',    443, 'tls'),
    ('www.twitch.tv',          'Twitch',    443, 'tls'),
    ('www.twitter.com',        'Twitter',   443, 'tls'),
    ('www.whatsapp.com',       'WhatsApp',  443, 'tls'),
    ('example.com',            'HTTP',       80, 'http'),
    ('api.example.com',        'HTTP',       80, 'http'),
    ('cdn.example.org',        'HTTP',     8080, 'http'),
]

DNS_DOMAINS = [
    'www.youtube.com',
    'www.google.com',
    'www.facebook.com',
    'api.tiktok.com',
    'www.netflix.com',
    'discord.com',
    'www.reddit.com',
    'github.com',
]

# Client IPs (one will be "blocked" in blocking tests)
CLIENT_IPS = [
    '192.168.1.100',
    '192.168.1.101',
    '192.168.1.50',   # <- This IP will be used for blocking tests
    '10.0.0.1',
    '10.0.0.2',
]

SERVER_IP = '203.0.113.1'

def random_client():
    return random.choice(CLIENT_IPS[:2])  # Normal clients

def random_port():
    return random.randint(49152, 65535)

# ---------------------------------------------------------------------------
# Generate a multi-packet TCP flow (SYN -> SYN-ACK -> ACK -> Data)
# ---------------------------------------------------------------------------
def generate_tcp_flow(out, ts, app_entry, client_ip, client_port, ground_truth):
    sni, app_name, dst_port, traffic_type = app_entry
    server_ip = f"203.0.113.{random.randint(1, 100)}"

    seq_c = random.randint(1000, 999999)  # client ISN
    seq_s = random.randint(1000, 999999)  # server ISN

    packets = []

    # SYN
    packets.append(make_tcp_packet(
        client_ip, server_ip, client_port, dst_port,
        seq_c, 0, 0x02))  # SYN

    # SYN-ACK
    packets.append(make_tcp_packet(
        server_ip, client_ip, dst_port, client_port,
        seq_s, seq_c + 1, 0x12))  # SYN+ACK

    # ACK
    packets.append(make_tcp_packet(
        client_ip, server_ip, client_port, dst_port,
        seq_c + 1, seq_s + 1, 0x10))  # ACK

    # Data packet with TLS Client Hello or HTTP GET
    if traffic_type == 'tls':
        payload = tls_client_hello(sni)
    else:
        payload = http_get(sni)

    packets.append(make_tcp_packet(
        client_ip, server_ip, client_port, dst_port,
        seq_c + 1, seq_s + 1, 0x18,  # PSH+ACK
        payload))

    # 2-5 more data packets (simulating continued connection)
    num_extra = random.randint(2, 5)
    for j in range(num_extra):
        extra_payload = bytes(random.randint(0, 255) for _ in range(random.randint(64, 512)))
        packets.append(make_tcp_packet(
            client_ip, server_ip, client_port, dst_port,
            seq_c + 1 + len(payload) + j * 256, seq_s + 1, 0x18,
            extra_payload))

    # FIN
    packets.append(make_tcp_packet(
        client_ip, server_ip, client_port, dst_port,
        seq_c + 100, seq_s + 1, 0x11))  # FIN+ACK

    for pkt_data in packets:
        ts_sec  = int(ts)
        ts_usec = int((ts - ts_sec) * 1e6)
        out.append((ts_sec, ts_usec, pkt_data))
        ts += random.uniform(0.0001, 0.001)

    # Record in ground truth
    flow_key = f"{client_ip}:{client_port}->{server_ip}:{dst_port}"
    ground_truth[flow_key] = {
        'sni': sni if traffic_type == 'tls' else None,
        'http_host': sni if traffic_type == 'http' else None,
        'app': app_name,
        'type': traffic_type,
        'packet_count': len(packets)
    }

    return ts

def generate_dns_flow(out, ts, domain, client_ip, ground_truth):
    client_port = random_port()
    server_ip   = '8.8.8.8'
    dns_payload = dns_query(domain)

    pkt_data = make_udp_packet(client_ip, server_ip, client_port, 53, dns_payload)
    ts_sec   = int(ts)
    ts_usec  = int((ts - ts_sec) * 1e6)
    out.append((ts_sec, ts_usec, pkt_data))

    flow_key = f"{client_ip}:{client_port}->8.8.8.8:53"
    ground_truth[flow_key] = {
        'dns_query': domain,
        'app': 'DNS',
        'type': 'dns',
        'packet_count': 1
    }

    return ts + random.uniform(0.001, 0.01)

# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------
def generate_pcap(filename, num_flows, ground_truth):
    packets_out = []
    ts = time.time() - 3600  # Start 1 hour ago

    for i in range(num_flows):
        client_ip   = random_client()
        client_port = random_port()

        # 80% TCP flows (TLS + HTTP), 20% DNS
        if random.random() < 0.80:
            app_entry = random.choice(APPS)
            ts = generate_tcp_flow(packets_out, ts, app_entry, client_ip, client_port, ground_truth)
        else:
            domain = random.choice(DNS_DOMAINS)
            ts = generate_dns_flow(packets_out, ts, domain, client_ip, ground_truth)

    # Special: add flows from the "blocked" IP 192.168.1.50
    for _ in range(10):
        client_ip   = '192.168.1.50'
        client_port = random_port()
        app_entry   = ('www.youtube.com', 'YouTube', 443, 'tls')
        ts = generate_tcp_flow(packets_out, ts, app_entry, client_ip, client_port, ground_truth)

    print(f"  Generated {len(packets_out)} packets from {len(ground_truth)} flows")

    # Write PCAP
    with open(filename, 'wb') as f:
        f.write(PCAP_GLOBAL_HEADER)
        for (ts_sec, ts_usec, data) in packets_out:
            f.write(pcap_packet_header(ts_sec, ts_usec, len(data)))
            f.write(data)

    return len(packets_out)

if __name__ == '__main__':
    print("DPI Test PCAP Generator")
    print("=" * 40)

    ground_truth = {}
    os.makedirs('test_data', exist_ok=True)

    # Small test PCAP (~500 packets)
    print("Generating test_small.pcap (~500 packets)...")
    n = generate_pcap('test_data/test_small.pcap', 50, ground_truth)
    print(f"  Written: test_data/test_small.pcap ({n} packets)")

    ground_truth_large = {}

    # Large benchmark PCAP (~50K packets)
    print("Generating test_large.pcap (~50K packets)...")
    n = generate_pcap('test_data/test_large.pcap', 5000, ground_truth_large)
    print(f"  Written: test_data/test_large.pcap ({n} packets)")

    # Ground truth JSON
    with open('test_data/ground_truth.json', 'w') as f:
        json.dump(ground_truth, f, indent=2)
    print("  Written: test_data/ground_truth.json")

    with open('test_data/ground_truth_large.json', 'w') as f:
        json.dump(ground_truth_large, f, indent=2)
    print("  Written: test_data/ground_truth_large.json")

    # Print summary
    tls_flows  = sum(1 for v in ground_truth_large.values() if v.get('type') == 'tls')
    http_flows = sum(1 for v in ground_truth_large.values() if v.get('type') == 'http')
    dns_flows  = sum(1 for v in ground_truth_large.values() if v.get('type') == 'dns')

    print(f"\nFlow breakdown (large):")
    print(f"  TLS flows:  {tls_flows}")
    print(f"  HTTP flows: {http_flows}")
    print(f"  DNS flows:  {dns_flows}")
    print(f"  Total:      {len(ground_truth_large)}")
    print("\nDone! Run 'dpi_simple test_data/test_small.pcap output.pcap' to test.")
