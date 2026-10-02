#!/usr/bin/env python3
"""
Network Packet Sniffer
Authorized/local network analysis only.

Linux/macOS: raw sockets normally require root privileges.
Windows: raw-socket behavior varies by OS and may require a packet-capture
driver/tool such as Npcap for broader capture support.
"""

import argparse
import logging
import socket
import struct
from collections import Counter

LOG_FILE = "network_traffic.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

def parse_ipv4_packet(packet):
    if len(packet) < 20:
        return None

    version_ihl = packet[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4

    if version != 4 or len(packet) < ihl:
        return None

    ttl = packet[8]
    protocol = packet[9]
    src = socket.inet_ntoa(packet[12:16])
    dst = socket.inet_ntoa(packet[16:20])

    transport = packet[ihl:]
    src_port = dst_port = None
    payload_length = 0

    if protocol == 6 and len(transport) >= 20:  # TCP
        src_port, dst_port = struct.unpack("!HH", transport[:4])
        data_offset = ((transport[12] >> 4) & 0x0F) * 4
        payload_length = max(0, len(transport) - data_offset)
    elif protocol == 17 and len(transport) >= 8:  # UDP
        src_port, dst_port = struct.unpack("!HH", transport[:4])
        payload_length = max(0, len(transport) - 8)
    else:
        payload_length = len(transport)

    return {
        "src": src,
        "dst": dst,
        "protocol": PROTOCOLS.get(protocol, f"PROTO-{protocol}"),
        "ttl": ttl,
        "src_port": src_port,
        "dst_port": dst_port,
        "payload_length": payload_length,
    }

def format_packet(info):
    ports = ""
    if info["src_port"] is not None:
        ports = f":{info['src_port']} -> :{info['dst_port']}"

    return (
        f"{info['protocol']:>5} | "
        f"{info['src']}{ports} -> {info['dst']}{'' if not ports else ''} | "
        f"TTL={info['ttl']} | payload={info['payload_length']} bytes"
    )

def sniff(interface=None, count=10):
    if not hasattr(socket, "AF_PACKET"):
        raise RuntimeError(
            "This raw-socket example requires a platform supporting AF_PACKET "
            "(commonly Linux). Use a packet-capture library/driver on Windows."
        )

    raw_socket = socket.socket(
        socket.AF_PACKET,
        socket.SOCK_RAW,
        socket.ntohs(0x0003)  # ETH_P_ALL
    )

    if interface:
        raw_socket.bind((interface, 0))

    stats = Counter()
    captured = 0

    print(f"[*] Capturing up to {count} IPv4 packets...")
    print("[*] Use only on networks/interfaces you are authorized to monitor.\n")

    try:
        while captured < count:
            packet, _ = raw_socket.recvfrom(65535)

            # Ethernet header is 14 bytes.
            if len(packet) < 14:
                continue

            ethertype = struct.unpack("!H", packet[12:14])[0]
            if ethertype != 0x0800:  # IPv4
                continue

            info = parse_ipv4_packet(packet[14:])
            if not info:
                continue

            captured += 1
            stats[info["protocol"]] += 1
            line = format_packet(info)

            print(line)
            logging.info(line)

    finally:
        raw_socket.close()

    print("\n=== Protocol Statistics ===")
    for protocol, total in stats.items():
        print(f"{protocol}: {total}")
        logging.info("STATISTICS | %s=%s", protocol, total)

def main():
    parser = argparse.ArgumentParser(
        description="IPv4 TCP/UDP raw packet sniffer for authorized analysis."
    )
    parser.add_argument("-i", "--interface", help="Network interface, e.g. eth0")
    parser.add_argument("-c", "--count", type=int, default=10,
                        help="Number of IPv4 packets to capture")
    args = parser.parse_args()

    if args.count <= 0:
        parser.error("--count must be greater than zero")

    try:
        sniff(args.interface, args.count)
    except PermissionError:
        print("[!] Permission denied. Run with elevated/root privileges.")
    except OSError as exc:
        print(f"[!] Socket error: {exc}")
    except RuntimeError as exc:
        print(f"[!] {exc}")

if __name__ == "__main__":
    main()
