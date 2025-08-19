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
