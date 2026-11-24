#!/usr/bin/env python3
"""ICMP Echo responder for Host B (and any end host)."""
import argparse
import json
import logging
import signal
import socket

from icmp import ECHO_REPLY, ECHO_REQUEST, build_echo, parse_icmp
from ipv4 import PROTO_ICMP, build_ipv4, parse_ipv4

log = logging.getLogger("host")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    cfg = json.load(open(a.config))
    me = cfg["overlay_ip"]
    gw = (cfg["gateway_ip"], int(cfg["gateway_port"]))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((cfg["bind_ip"], int(cfg["bind_port"])))
    sock.settimeout(0.5)
    running = [True]
    signal.signal(signal.SIGINT, lambda *_: running.__setitem__(0, False))
    signal.signal(signal.SIGTERM, lambda *_: running.__setitem__(0, False))
    log.info("%s: echo responder %s up (gateway %s:%d)", cfg["name"], me, *gw)
    while running[0]:
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        try:
            ip = parse_ipv4(data)
        except ValueError as e:
            log.warning("malformed packet: %s", e)
            continue
        if not ip["checksum_ok"]:
            log.warning("bad IPv4 checksum, dropped")
            continue
        if ip["dst"] != me or ip["proto"] != PROTO_ICMP:
            continue
        try:
            ic = parse_icmp(ip["payload"])
        except ValueError:
            continue
        if ic["type"] == ECHO_REQUEST and ic["checksum_ok"]:
            log.info("echo request from %s seq=%d arrived with ttl=%d",
                     ip["src"], ic["seq"], ip["ttl"])
            reply = build_ipv4(me, ip["src"], PROTO_ICMP,
                               build_echo(ECHO_REPLY, ic["ident"], ic["seq"], ic["body"]),
                               ttl=64)
            sock.sendto(reply, gw)


if __name__ == "__main__":
    main()
