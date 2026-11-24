"""F3 (config loader + linear LPM) and F4 (binary-trie LPM).

Router code only ever calls RoutingTable.lookup(dst); the backend
('linear' or 'trie') is swappable with set_backend() so Phase 2 / F4 is a
drop-in replacement.
"""
import ipaddress
import json
import socket
import struct
from collections import namedtuple

Route = namedtuple("Route", "network mask prefix_len prefix out_ip out_port "
                            "local_bind_ip local_bind_port")


def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


class BinaryTrie:
    """Unibit trie; node = [child0, child1, value]."""

    def __init__(self):
        self.root = [None, None, None]

    def insert(self, network: int, plen: int, value):
        node = self.root
        for i in range(plen):
            bit = (network >> (31 - i)) & 1
            nxt = node[bit]
            if nxt is None:
                nxt = [None, None, None]
                node[bit] = nxt
            node = nxt
        node[2] = value

    def lookup(self, ip: int):
        node = self.root
        best = node[2]
        for shift in range(31, -1, -1):
            node = node[(ip >> shift) & 1]
            if node is None:
                break
            if node[2] is not None:
                best = node[2]
        return best


class RoutingTable:
    def __init__(self, routes=None, backend: str = "linear"):
        self.routes = []
        self._trie = BinaryTrie()
        self._seen = set()
        self._backend = "linear"
        for r in routes or []:
            self.add_route(r)
        self.set_backend(backend)

    # ---- construction -------------------------------------------------
    def add_route(self, r: dict):
        net = ipaddress.ip_network(r["prefix"], strict=True)
        network, plen = int(net.network_address), net.prefixlen
        if (network, plen) in self._seen:
            raise ValueError("duplicate prefix %s" % r["prefix"])
        self._seen.add((network, plen))
        mask = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF if plen else 0
        route = Route(network, mask, plen, str(net), r["out_ip"], int(r["out_port"]),
                      r["local_bind_ip"], int(r.get("local_bind_port", 5000)))
        self.routes.append(route)
        self._trie.insert(network, plen, route)

    @classmethod
    def from_config(cls, path: str, backend: str = "linear"):
        with open(path) as f:
            return cls.from_config_dict(json.load(f), backend)

    @classmethod
    def from_config_dict(cls, cfg: dict, backend: str = "linear"):
        return cls(cfg["routes"], backend)

    # ---- lookup -------------------------------------------------------
    def set_backend(self, name: str):
        if name not in ("linear", "trie"):
            raise ValueError("backend must be 'linear' or 'trie'")
        self._backend = name

    @staticmethod
    def _as_int(dst):
        return dst if isinstance(dst, int) else ip_to_int(dst)

    def lookup_linear(self, dst):
        d = self._as_int(dst)
        best = None
        for r in self.routes:
            if (d & r.mask) == r.network and (best is None or r.prefix_len > best.prefix_len):
                best = r
        return best

    def lookup_trie(self, dst):
        return self._trie.lookup(self._as_int(dst))

    def lookup(self, dst):
        """Standalone interface used by router.py. Returns Route or None."""
        if self._backend == "trie":
            return self.lookup_trie(dst)
        return self.lookup_linear(dst)

    def __len__(self):
        return len(self.routes)
