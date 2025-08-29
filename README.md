# Packet Sniffer

This repository contains my custom-built packet sniffer project — a minimal version of Wireshark that I wrote from scratch.  
It captures raw network packets, dissects Ethernet/IP/TCP/UDP headers, and can save captures to a standard `.pcap` file that opens in Wireshark.  

I built this to deepen my understanding of network protocols, packet structures, and raw socket programming.

---

## Features

- Capture live packets directly from a network interface (requires root/admin).
- Decode Ethernet, IPv4, IPv6, TCP, and UDP headers by hand.
- Print packet summaries in real time (like `tcpdump`).
- Save full packet data to `.pcap` files for later analysis in Wireshark.
- Command-line options for interface selection, packet count, snap length, and capture output.

---

## How It Works

The sniffer uses a raw socket (`AF_PACKET` on Linux) to receive Ethernet frames straight from the NIC.  
Each packet is then parsed step by step:

1. **Ethernet header** → get source/destination MAC + Ethertype.  
2. **IP header** (IPv4 or IPv6) → get source/destination IP, protocol number.  
3. **TCP/UDP header** → get ports, flags, payload length.  
4. The program prints a human-readable summary and optionally writes the raw packet to a `.pcap` file with proper headers.  

This means you can capture with this tool, then open the same capture in Wireshark to cross-check.

---

## Requirements

- Python 3.8+
- Linux (tested on Ubuntu, but works on most distros)
- Root/admin privileges (raw sockets require elevated permissions)

---

## Usage

Clone the repo:

```bash
git clone https://github.com/yourusername/packet-sniffer.git
cd packet-sniffer
```

Run the sniffer on an interface (requires sudo/root):
```bash
sudo python3 sniff.py -i eth0
```

Common options:

Capture only 20 packets:
```bash
sudo python3 sniff.py -i eth0 -n 20
```

Save to a .pcap file for later analysis:
```bash
sudo python3 sniff.py -i eth0 -w capture.pcap
```

You’ll see live packet summaries printed in your terminal, for example:
```bash
Pv4 proto=1 192.168.0.12 → 8.8.8.8 len=64
IPv4 proto=1 8.8.8.8 → 192.168.0.12 len=64
ETH 40:3f:8c:85:2b:0a → ff:ff:ff:ff:ff:ff 0x8f86
IPv4 proto=1 192.168.0.12 → 8.8.8.8 len=64
IPv4 proto=1 8.8.8.8 → 192.168.0.12 len=64
IPv4 TCP 192.168.0.12:45352 → 216.58.204.67:80 len=0
IPv4 TCP 192.168.0.12:45346 → 216.58.204.67:80 len=0
IPv4 TCP 216.58.204.67:80 → 192.168.0.12:45352 len=0
IPv4 TCP 216.58.204.67:80 → 192.168.0.12:45346 len=0
IPv4 proto=1 192.168.0.12 → 8.8.8.8 len=64
IPv4 proto=1 8.8.8.8 → 192.168.0.12 len=64
IPv4 proto=1 192.168.0.12 → 8.8.8.8 len=64
IPv4 proto=1 8.8.8.8 → 192.168.0.12 len=64
IPv4 proto=1 192.168.0.12 → 8.8.8.8 len=64
IPv4 proto=1 8.8.8.8 → 192.168.0.12 len=64
ETH 40:3f:8c:85:2b:0a → ff:ff:ff:ff:ff:ff 0x8f83
ETH 44:05:3f:80:f2:f4 → 00:0c:29:d7:7d:60 0x0806
ETH 00:0c:29:d7:7d:60 → 44:05:3f:80:f2:f4 0x0806
```
Open in Wireshark

To confirm the capture:

Run the sniffer with the -w flag to write packets into capture.pcap.
```bash
sudo python3 sniff.py -i eth0 -n 50 -w capture.pcap
```

Open Wireshark:
```bash
wireshark capture.pcap
```

You’ll see the same packets you captured, now fully decoded with Wireshark’s protocol dissectors.

## Repository Contents

- **sniff.py** → The Python sniffer script (run this to capture packets).

- **capture.pcap** → Example capture file you can open in Wireshark to see how the sniffer’s output looks.


