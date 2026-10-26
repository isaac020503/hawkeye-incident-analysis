#!/usr/bin/env python3
"""pcap_summary.py - quick triage of a classic .pcap file (Ethernet/IPv4).

Pure standard library, no installs needed.

Reports:
  * packet count, duration, protocol mix
  * busiest connections
  * DNS queries
  * HTTP requests, flagging downloads of Windows executables
  * outbound SMTP from hosts (a common data-exfiltration channel)

Usage:
    python3 pcap_summary.py capture.pcap
"""
import collections
import socket
import struct
import sys

SMTP_PORTS = {25, 465, 587}
HTTP_METHODS = (b"GET ", b"POST", b"HEAD", b"PUT ")


def read_packets(data):
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise SystemExit("Not a classic .pcap file (pcapng is not supported).")
    offset = 24
    while offset + 16 <= len(data):
        sec, usec, caplen, _ = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        yield sec + usec / 1e6, data[offset:offset + caplen]
        offset += caplen


def parse_dns_name(payload):
    i, parts = 12, []
    while i < len(payload) and payload[i]:
        length = payload[i]
        parts.append(payload[i + 1:i + 1 + length].decode("latin1"))
        i += length + 1
    return ".".join(parts)


def analyse(path):
    data = open(path, "rb").read()
    first = last = None
    count = 0
    protocols = collections.Counter()
    conversations = collections.Counter()
    dns, http, smtp = [], [], {}

    for ts, pkt in read_packets(data):
        count += 1
        first = first or ts
        last = ts
        if len(pkt) < 34 or struct.unpack(">H", pkt[12:14])[0] != 0x0800:
            protocols["non-IPv4"] += 1
            continue
        ip = pkt[14:]
        ihl = (ip[0] & 15) * 4
        proto = ip[9]
        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        l4 = ip[ihl:]

        if proto == 6 and len(l4) >= 20:
            protocols["TCP"] += 1
            sport, dport = struct.unpack(">HH", l4[:4])
            conversations[(src, dst, dport)] += 1
            payload = l4[(l4[12] >> 4) * 4:struct.unpack(">H", ip[2:4])[0] - ihl]
            if payload[:4] in HTTP_METHODS:
                lines = payload.split(b"\r\n")
                host = next((l[6:].decode("latin1") for l in lines
                             if l.lower().startswith(b"host:")), "")
                http.append((ts - first, src, dst, host, lines[0][:100].decode("latin1")))
            if dport in SMTP_PORTS and l4[13] & 2 and not l4[13] & 16:  # SYN only
                smtp.setdefault((src, dst, dport), []).append(ts - first)
        elif proto == 17 and len(l4) >= 8:
            protocols["UDP"] += 1
            _, dport = struct.unpack(">HH", l4[:4])
            payload = l4[8:]
            if dport == 53 and len(payload) > 12 and not payload[2] & 0x80:
                dns.append((ts - first, src, parse_dns_name(payload)))
        else:
            protocols["other"] += 1

    return count, (last or 0) - (first or 0), protocols, conversations, dns, http, smtp


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    count, duration, protocols, conversations, dns, http, smtp = analyse(sys.argv[1])

    print(f"Packets: {count}   Duration: {duration:.0f}s   Protocols: {dict(protocols)}")

    print("\nBusiest connections (src -> dst:port, packets)")
    for (src, dst, port), n in conversations.most_common(8):
        print(f"  {src} -> {dst}:{port}  {n}")

    print("\nDNS queries (first seen)")
    seen = set()
    for t, src, name in dns:
        if name not in seen:
            seen.add(name)
            print(f"  +{t:6.0f}s  {src}  {name}")

    print("\nHTTP requests")
    for t, src, dst, host, line in http:
        flag = "   <-- ALERT: executable download over HTTP" if ".exe" in line.lower() else ""
        print(f"  +{t:6.0f}s  {src} -> {dst}  {host}  {line}{flag}")

    print("\nOutbound SMTP sessions (possible exfiltration)")
    for (src, dst, port), times in smtp.items():
        stamps = ", ".join(f"+{t:.0f}s" for t in times)
        print(f"  ALERT: {src} -> {dst}:{port}  {len(times)} sessions at {stamps}")
    if not smtp:
        print("  none")


if __name__ == "__main__":
    main()
