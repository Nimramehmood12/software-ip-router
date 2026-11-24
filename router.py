#!/usr/bin/env python3
"""F2 - software IPv4 router. One UDP datagram == one raw IPv4 packet.

Pipeline: recv -> parse -> verify checksum -> TTL check -> TTL-1 + new checksum
          -> lookup() -> pcap log -> send to next hop.

Phase 2 hooks (override or fill in): lookup(), on_ttl_expired(), on_no_route(),
on_local_delivery().
"""
import argparse
import json
import logging
import selectors
import signal
import socket
import sys

from ipv4 import decrement_ttl, parse_ipv4
from pcap_logger import PcapWriter
from routing_table import RoutingTable

log = logging.getLogger("router")


class Router:
    def __init__(self, cfg: dict, pcap_path: str = None, backend: str = "linear"):
        self.name = cfg["name"]
        self.local_ips = set(cfg.get("local_ips", []))
        self.table = RoutingTable.from_config_dict(cfg, backend)
        self.socks = {}                          # (bind_ip, port) -> UDP socket
        for itf in cfg["interfaces"]:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((itf["bind_ip"], int(itf.get("bind_port", 5000))))
            self.socks[(itf["bind_ip"], int(itf.get("bind_port", 5000)))] = s
        self.pcap = PcapWriter(pcap_path) if pcap_path else None
        self.running = True
        self.stats = dict(rx=0, fwd=0, bad_header=0, bad_checksum=0,
                          ttl_expired=0, no_route=0, local=0, send_err=0)

    # ---------------- hooks for Phase 2 ----------------
    def lookup(self, dst_int: int):
        """Standalone lookup interface (F3 linear now, F4 trie via --lookup trie)."""
        return self.table.lookup(dst_int)

    def on_ttl_expired(self, raw: bytes, ip: dict, in_sock):
        """F5 hook: send ICMP Time Exceeded (type 11, code 0) to ip['src'].
        Phase 1: just count and drop."""
        self.stats["ttl_expired"] += 1
        log.info("%s: TTL expired %s -> %s (drop; ICMP not implemented yet)",
                 self.name, ip["src"], ip["dst"])

    def on_no_route(self, raw: bytes, ip: dict, in_sock):
        """F5 hook: send ICMP Destination Unreachable (type 3, code 0) to ip['src'].
        Phase 1: just count and drop."""
        self.stats["no_route"] += 1
        log.info("%s: no route to %s (drop; ICMP not implemented yet)",
                 self.name, ip["dst"])

    def on_local_delivery(self, raw: bytes, ip: dict, in_sock):
        """Packet addressed to one of this router's own IPs (Phase 2: answer pings)."""
        self.stats["local"] += 1
        log.info("%s: packet for router itself from %s (ignored in Phase 1)",
                 self.name, ip["src"])

    # ---------------- data plane ----------------
    def handle(self, data: bytes, addr, in_sock):
        self.stats["rx"] += 1
        try:
            ip = parse_ipv4(data)
        except ValueError as e:
            self.stats["bad_header"] += 1
            log.warning("%s: malformed packet from %s dropped: %s", self.name, addr, e)
            return
        if not ip["checksum_ok"]:
            self.stats["bad_checksum"] += 1
            log.warning("%s: bad IPv4 checksum from %s dropped", self.name, addr)
            return
        if ip["dst"] in self.local_ips:
            self.on_local_delivery(data, ip, in_sock)
            return
        if ip["ttl"] <= 1:
            self.on_ttl_expired(data, ip, in_sock)
            return
        pkt = decrement_ttl(data)
        route = self.lookup(ip["dst_int"])
        if route is None:
            self.on_no_route(data, ip, in_sock)
            return
        if self.pcap:
            self.pcap.write(pkt)
        out = self.socks.get((route.local_bind_ip, route.local_bind_port))
        if out is None:
            log.error("%s: route %s uses unknown local socket %s:%d", self.name,
                      route.prefix, route.local_bind_ip, route.local_bind_port)
            return
        try:
            out.sendto(pkt, (route.out_ip, route.out_port))
            self.stats["fwd"] += 1
            log.debug("%s: %s -> %s ttl %d->%d via %s:%d", self.name, ip["src"],
                      ip["dst"], ip["ttl"], ip["ttl"] - 1, route.out_ip, route.out_port)
        except OSError as e:
            self.stats["send_err"] += 1
            log.warning("%s: send failed: %s", self.name, e)

    def run(self):
        sel = selectors.DefaultSelector()
        for s in self.socks.values():
            sel.register(s, selectors.EVENT_READ)
        log.info("%s: up, %d routes, lookup=%s, listening on %s", self.name,
                 len(self.table), self.table._backend, sorted(self.socks))
        try:
            while self.running:
                for key, _ in sel.select(timeout=0.5):
                    try:
                        data, addr = key.fileobj.recvfrom(65535)
                    except OSError as e:
                        log.warning("recv error: %s", e)
                        continue
                    self.handle(data, addr, key.fileobj)
        finally:
            if self.pcap:
                self.pcap.close()
            log.info("%s: stats %s", self.name, self.stats)


def main():
    ap = argparse.ArgumentParser(description="Software IPv4 router over UDP overlay")
    ap.add_argument("--config", required=True)
    ap.add_argument("--pcap", help="raw-IP pcap output path")
    ap.add_argument("--lookup", choices=["linear", "trie"], default="linear")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    with open(a.config) as f:
        cfg = json.load(f)
    r = Router(cfg, a.pcap, a.lookup)

    def stop(*_):
        r.running = False
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    r.run()


if __name__ == "__main__":
    sys.exit(main())
