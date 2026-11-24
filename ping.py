#!/usr/bin/env python3
"""F6 - overlay ping. Sends ICMP Echo Requests inside our own IPv4 packets
over UDP into the first router and reports RTT / loss statistics."""
import argparse
import json
import os
import socket
import struct
import sys
import time

from icmp import (DEST_UNREACHABLE, ECHO_REPLY, ECHO_REQUEST, TIME_EXCEEDED,
                  build_echo, parse_icmp)
from ipv4 import PROTO_ICMP, build_ipv4, parse_ipv4


def quoted_seq(body: bytes, ident: int):
    """Extract (seq) from the original echo quoted inside an ICMP error, if ours."""
    try:
        ihl = (body[0] & 0xF) * 4
        _t, _c, _s, qid, qseq = struct.unpack("!BBHHH", body[ihl:ihl + 8])
        return qseq if qid == ident else None
    except (IndexError, struct.error):
        return None


def main():
    ap = argparse.ArgumentParser(description="Overlay ping")
    ap.add_argument("--config", required=True, help="host JSON (e.g. configs/hostA.json)")
    ap.add_argument("--dst", default="10.0.6.2", help="overlay destination IP")
    ap.add_argument("-c", "--count", type=int, default=4)
    ap.add_argument("-i", "--interval", type=float, default=1.0)
    ap.add_argument("-W", "--timeout", type=float, default=2.0)
    ap.add_argument("-s", "--size", type=int, default=56, help="ICMP payload bytes (>=8)")
    ap.add_argument("-t", "--ttl", type=int, default=64)
    a = ap.parse_args()

    cfg = json.load(open(a.config))
    src = cfg["overlay_ip"]
    gw = (cfg["gateway_ip"], int(cfg["gateway_port"]))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((cfg["bind_ip"], int(cfg["bind_port"])))
    ident = os.getpid() & 0xFFFF
    rtts, sent, errors = [], 0, 0

    print("PING %s from %s via %s:%d, %d bytes of data" % (a.dst, src, gw[0], gw[1], a.size))
    try:
        for seq in range(a.count):
            payload = (struct.pack("!d", time.time()) + bytes(range(256)) * 8)[:max(a.size, 8)]
            pkt = build_ipv4(src, a.dst, PROTO_ICMP,
                             build_echo(ECHO_REQUEST, ident, seq, payload), ttl=a.ttl)
            t0 = time.perf_counter()
            sock.sendto(pkt, gw)
            sent += 1
            deadline = t0 + a.timeout
            got = False
            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                try:
                    data, _ = sock.recvfrom(65535)
                except socket.timeout:
                    break
                t1 = time.perf_counter()
                try:
                    ip = parse_ipv4(data)
                    if not ip["checksum_ok"] or ip["proto"] != PROTO_ICMP:
                        continue
                    ic = parse_icmp(ip["payload"])
                except ValueError:
                    continue
                if not ic["checksum_ok"]:
                    continue
                if ic["type"] == ECHO_REPLY and ic.get("ident") == ident and ic.get("seq") == seq:
                    rtt = (t1 - t0) * 1000
                    rtts.append(rtt)
                    print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms" % (
                        len(ic["body"]) + 8, ip["src"], seq, ip["ttl"], rtt))
                    got = True
                    break
                if ic["type"] in (TIME_EXCEEDED, DEST_UNREACHABLE) and quoted_seq(ic["body"], ident) == seq:
                    what = "Time to live exceeded" if ic["type"] == TIME_EXCEEDED else \
                        "Destination unreachable"
                    print("From %s icmp_seq=%d %s" % (ip["src"], seq, what))
                    errors += 1
                    got = True
                    break
            if not got:
                print("Request timeout for icmp_seq=%d" % seq)
            if seq < a.count - 1:
                time.sleep(max(0, a.interval - (time.perf_counter() - t0)))
    except KeyboardInterrupt:
        pass

    loss = 100.0 * (sent - len(rtts)) / sent if sent else 0.0
    print("\n--- %s ping statistics ---" % a.dst)
    print("%d packets transmitted, %d received, %.1f%% packet loss" % (sent, len(rtts), loss))
    if rtts:
        print("rtt min/avg/max = %.3f/%.3f/%.3f ms" % (min(rtts), sum(rtts) / len(rtts), max(rtts)))
    return 0 if rtts else 1


if __name__ == "__main__":
    sys.exit(main())
