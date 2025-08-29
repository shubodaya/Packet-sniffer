#!/usr/bin/env python3
import argparse, socket, struct, time, os

PCAP_GLOBAL_HDR = struct.pack(
    "<IHHIIII",
    0xa1b2c3d4,  # magic
    2, 4,        # version
    0, 0,        # tz, sigfigs
    65535,       # snaplen
    1            # LINKTYPE_ETHERNET
)

def write_pcap_packet(fh, ts_sec, ts_usec, data):
    fh.write(struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)))
    fh.write(data)

def mac(addr):
    return ":".join(f"{b:02x}" for b in addr)

def ipv4(addr):
    return ".".join(map(str, addr))

def parse_eth(frame):
    if len(frame) < 14:
        return None
    dst, src, etype = struct.unpack("!6s6sH", frame[:14])
    return {
        "dst": mac(dst),
        "src": mac(src),
        "etype": etype,
        "payload": frame[14:]
    }

def parse_ipv4(pkt):
    if len(pkt) < 20:
        return None
    vihl, tos, total_len, ident, flags_frag, ttl, proto, csum, src, dst = struct.unpack("!BBHHHBBHII", pkt[:20])
    version, ihl = vihl >> 4, vihl & 0x0F
    if version != 4 or len(pkt) < ihl*4:
        return None
    return {
        "ihl": ihl,
        "proto": proto,
        "src": ipv4(struct.pack("!I", src)),
        "dst": ipv4(struct.pack("!I", dst)),
        "payload": pkt[ihl*4: total_len] if total_len <= len(pkt) else pkt[ihl*4:]
    }

def parse_ipv6(pkt):
    if len(pkt) < 40:
        return None
    ver_tc_fl, payload_len, nxt, hop = struct.unpack("!IHBB", pkt[:8])
    version = ver_tc_fl >> 28
    if version != 6:
        return None
    src = socket.inet_ntop(socket.AF_INET6, pkt[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, pkt[24:40])
    payload = pkt[40:40+payload_len] if 40+payload_len <= len(pkt) else pkt[40:]
    return {"nxt": nxt, "src": src, "dst": dst, "payload": payload}

def parse_tcp(pkt):
    if len(pkt) < 20:
        return None
    srcp, dstp, seq, ack, off_res_flags, win, csum, urgp = struct.unpack("!HHIIHHHH", pkt[:20])
    data_off = (off_res_flags >> 12) & 0xF
    hdr_len = data_off * 4
    if len(pkt) < hdr_len:
        return None
    flags = off_res_flags & 0x01FF
    return {
        "srcp": srcp, "dstp": dstp, "flags": flags,
        "payload": pkt[hdr_len:]
    }

def parse_udp(pkt):
    if len(pkt) < 8:
        return None
    srcp, dstp, length, csum = struct.unpack("!HHHH", pkt[:8])
    return {
        "srcp": srcp, "dstp": dstp,
        "payload": pkt[8:length] if length <= len(pkt) else pkt[8:]
    }

def main():
    ap = argparse.ArgumentParser(description="Tiny packet sniffer (Linux, raw socket)")
    ap.add_argument("-i", "--iface", required=True, help="Interface, e.g. eth0, wlan0")
    ap.add_argument("-n", "--count", type=int, default=0, help="Stop after N packets (0 = infinite)")
    ap.add_argument("-w", "--write", help="Write to pcap file")
    ap.add_argument("--snaplen", type=int, default=65535, help="Bytes per packet to capture")
    
    # --- New filtering options ---
    ap.add_argument("--proto", choices=["tcp","udp","icmp"], help="Only show specific protocol")
    ap.add_argument("--src", help="Only packets from this source IP")
    ap.add_argument("--dst", help="Only packets to this destination IP")
    ap.add_argument("--sport", type=int, help="Only packets from this source port")
    ap.add_argument("--dport", type=int, help="Only packets to this destination port")
    
    args = ap.parse_args()

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8*1024*1024)
    s.bind((args.iface, 0))

    fh = None
    if args.write:
        fh = open(args.write, "wb")
        fh.write(PCAP_GLOBAL_HDR)

    seen = 0
    try:
        while True:
            data, sa = s.recvfrom(args.snaplen)
            ts = time.time()
            ts_sec = int(ts)
            ts_usec = int((ts - ts_sec) * 1_000_000)

            if fh:
                write_pcap_packet(fh, ts_sec, ts_usec, data)

            eth = parse_eth(data)
            if not eth: 
                continue

            line = f"ETH {eth['src']} → {eth['dst']} 0x{eth['etype']:04x}"
            match = True  # assume packet passes filter by default

            if eth["etype"] == 0x0800:  # IPv4
                ip = parse_ipv4(eth["payload"])
                if ip:
                    proto_name = None
                    if ip["proto"] == 6:
                        tcp = parse_tcp(ip["payload"])
                        proto_name = "tcp"
                        if tcp:
                            line = f"IPv4 TCP {ip['src']}:{tcp['srcp']} → {ip['dst']}:{tcp['dstp']} len={len(tcp['payload'])}"
                            if args.sport and tcp['srcp'] != args.sport:
                                match = False
                            if args.dport and tcp['dstp'] != args.dport:
                                match = False
                    elif ip["proto"] == 17:
                        udp = parse_udp(ip["payload"])
                        proto_name = "udp"
                        if udp:
                            line = f"IPv4 UDP {ip['src']}:{udp['srcp']} → {ip['dst']}:{udp['dstp']} len={len(udp['payload'])}"
                            if args.sport and udp['srcp'] != args.sport:
                                match = False
                            if args.dport and udp['dstp'] != args.dport:
                                match = False
                    else:
                        line = f"IPv4 proto={ip['proto']} {ip['src']} → {ip['dst']} len={len(ip['payload'])}"
                    
                    # IP filters
                    if args.src and ip['src'] != args.src:
                        match = False
                    if args.dst and ip['dst'] != args.dst:
                        match = False
                    if args.proto and proto_name != args.proto:
                        match = False

            elif eth["etype"] == 0x86DD:  # IPv6
                ip6 = parse_ipv6(eth["payload"])
                if ip6:
                    proto_name = None
                    if ip6["nxt"] == 6:
                        tcp = parse_tcp(ip6["payload"])
                        proto_name = "tcp"
                        if tcp:
                            line = f"IPv6 TCP {ip6['src']}:{tcp['srcp']} → {ip6['dst']}:{tcp['dstp']} len={len(tcp['payload'])}"
                            if args.sport and tcp['srcp'] != args.sport:
                                match = False
                            if args.dport and tcp['dstp'] != args.dport:
                                match = False
                    elif ip6["nxt"] == 17:
                        udp = parse_udp(ip6["payload"])
                        proto_name = "udp"
                        if udp:
                            line = f"IPv6 UDP {ip6['src']}:{udp['srcp']} → {ip6['dst']}:{udp['dstp']} len={len(udp['payload'])}"
                            if args.sport and udp['srcp'] != args.sport:
                                match = False
                            if args.dport and udp['dstp'] != args.dport:
                                match = False
                    else:
                        line = f"IPv6 nxt={ip6['nxt']} {ip6['src']} → {ip6['dst']} len={len(ip6['payload'])}"

                    if args.src and ip6['src'] != args.src:
                        match = False
                    if args.dst and ip6['dst'] != args.dst:
                        match = False
                    if args.proto and proto_name != args.proto:
                        match = False

            if match:
                print(line)
                seen += 1
                if args.count and seen >= args.count:
                    break

    except KeyboardInterrupt:
        pass
    finally:
        if fh:
            fh.close()


if __name__ == "__main__":
    # Require root to open AF_PACKET
    if os.geteuid() != 0:
        raise SystemExit("Run as root: sudo python3 sniff.py -i eth0")
    main()

