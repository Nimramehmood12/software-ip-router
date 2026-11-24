#!/usr/bin/env python3
"""Offline sanity check of a raw-IP pcap written by pcap_logger.py:
prints every packet and counts IPv4 checksum errors (same thing Wireshark
validates). Usage: python3 pcap_check.py pcaps/r1.pcap [...]"""
import struct
import sys

from ipv4 import parse_ipv4


def check(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        magic, vmaj, vmin, _, _, snap, link = struct.unpack("<IHHiIII", gh)
        assert magic == 0xA1B2C3D4, "bad magic"
        print("%s: pcap v%d.%d linktype=%d %s" % (path, vmaj, vmin, link,
              "(RAW IPv4 OK)" if link == 101 else "(NOT raw-IP!)"))
        n = bad = 0
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                break
            sec, usec, caplen, origlen = struct.unpack("<IIII", rh)
            pkt = f.read(caplen)
            p = parse_ipv4(pkt)
            n += 1
            bad += not p["checksum_ok"]
            print("  #%d %s -> %s ttl=%d proto=%d len=%d csum=%s" % (
                n, p["src"], p["dst"], p["ttl"], p["proto"], p["total_length"],
                "OK" if p["checksum_ok"] else "BAD"))
        print("  %d packets, %d checksum errors" % (n, bad))
        return bad


if __name__ == "__main__":
    sys.exit(1 if sum(check(p) for p in sys.argv[1:]) else 0)
