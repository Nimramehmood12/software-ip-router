#!/usr/bin/env python3
"""F10 (lookup part) - linear vs binary-trie LPM scaling.
For each table size: 3 runs, mean and standard deviation of per-lookup time.
Usage: python3 bench_lookup.py [--lookups 2000] [--sizes 10 100 1000 10000]
Writes results/lookup_scaling.csv"""
import argparse
import csv
import os
import random
import statistics
import time

from routing_table import RoutingTable, ip_to_int


def make_table(n, rng):
    routes, seen = [], set()
    # anchor routes so the 6 overlay subnets always exist
    for s in range(1, 7):
        routes.append({"prefix": "10.0.%d.0/24" % s, "out_ip": "127.0.0.1",
                       "out_port": 5000, "local_bind_ip": "127.0.0.1"})
        seen.add(("10.0.%d.0" % s, 24))
    while len(routes) < n:
        plen = rng.randint(8, 28)
        net = rng.getrandbits(32) & ((0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF)
        ip = "%d.%d.%d.%d" % (net >> 24, (net >> 16) & 255, (net >> 8) & 255, net & 255)
        if (ip, plen) in seen:
            continue
        seen.add((ip, plen))
        routes.append({"prefix": "%s/%d" % (ip, plen), "out_ip": "127.0.0.1",
                       "out_port": 5000, "local_bind_ip": "127.0.0.1"})
    return routes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="+", default=[10, 100, 1000, 10000])
    ap.add_argument("--lookups", type=int, default=2000)
    ap.add_argument("--runs", type=int, default=3)
    a = ap.parse_args()
    os.makedirs("results", exist_ok=True)
    rows = []
    print("%8s %8s %14s %12s" % ("routes", "backend", "mean us/lookup", "stdev"))
    for n in a.sizes:
        rng = random.Random(n)
        table = RoutingTable(make_table(n, rng))
        for run in range(a.runs):                       # correctness spot-check
            for _ in range(200):
                d = rng.getrandbits(32)
                assert table.lookup_linear(d) == table.lookup_trie(d), "LPM mismatch!"
        res = {"linear": [], "trie": []}
        for run in range(a.runs):
            dsts = [ip_to_int("10.0.%d.%d" % (rng.randint(1, 6), rng.randint(1, 254)))
                    if rng.random() < 0.5 else rng.getrandbits(32) for _ in range(a.lookups)]
            for name, fn in (("linear", table.lookup_linear), ("trie", table.lookup_trie)):
                t0 = time.perf_counter_ns()
                for d in dsts:
                    fn(d)
                res[name].append((time.perf_counter_ns() - t0) / len(dsts) / 1000.0)
        for name in ("linear", "trie"):
            m, sd = statistics.mean(res[name]), statistics.stdev(res[name])
            rows.append([n, name, round(m, 3), round(sd, 3)] + [round(x, 3) for x in res[name]])
            print("%8d %8s %14.3f %12.3f" % (n, name, m, sd))
    with open("results/lookup_scaling.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["table_size", "backend", "mean_us_per_lookup", "stdev_us"] +
                   ["run%d_us" % (i + 1) for i in range(a.runs)])
        w.writerows(rows)
    print("saved results/lookup_scaling.csv")


if __name__ == "__main__":
    main()
