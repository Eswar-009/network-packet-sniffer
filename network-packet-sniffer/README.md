# Network Packet Sniffer

A Python command-line packet sniffer for authorized/local network analysis.
It captures IPv4 traffic through a raw socket, parses IP headers, extracts
TCP/UDP ports, reports payload sizes, and records protocol statistics.

## Features

- Raw socket listener
- IPv4 header parsing
- Source/destination IP extraction
- TCP and UDP port parsing
- Payload length reporting
- Protocol statistics
- File-based traffic logging

## Requirements

- Python 3.9+
- Linux is recommended for the included `AF_PACKET` raw-socket implementation
- Elevated/root privileges are normally required

## Run

Linux example:

```bash
sudo python3 packet_sniffer.py -i eth0 -c 10
```

If the interface is omitted:

```bash
sudo python3 packet_sniffer.py -c 10
```

## Windows Note

The included raw-socket capture path uses Linux-style `AF_PACKET`. On Windows,
broader packet capture normally requires a capture driver such as Npcap and a
suitable capture library. The parser functions can still be studied/tested
with captured packet bytes.

## Output

The program prints packet summaries such as:

```text
  TCP | 192.0.2.10:443 -> 192.0.2.20 | TTL=64 | payload=128 bytes
  UDP | 192.0.2.20:5353 -> 224.0.0.251 | TTL=255 | payload=72 bytes
```

Traffic summaries are written to `network_traffic.log`.

## Safety

Use packet capture only on systems and networks where you have explicit
authorization. This project is intended for defensive network monitoring,
learning, and lab environments.
