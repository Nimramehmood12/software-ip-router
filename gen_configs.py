#!/usr/bin/env python3
"""Generate configs/{r1..r5,hostA,hostB}.json for the chain
hostA - r1 - r2 - r3 - r4 - r5 - hostB.

Subnet k (10.0.k.0/24) joins node k-1 (left, .1) and node k (right, .2) where
node 0 = hostA, nodes 1..5 = r1..r5, node 6 = hostB.

  --mode netns     UDP sockets bind/send on the real veth IPs (10.0.k.x)
  --mode loopback  same overlay IPs, but UDP uses 127.0.k.x on the host's lo,
                   so everything can be tested without root/namespaces.
"""
import argparse
import json
import os

PORT = 5000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["netns", "loopback"], default="netns")
    ap.add_argument("--outdir", default="configs")
    a = ap.parse_args()
    u = (lambda ip: ip.replace("10.", "127.", 1)) if a.mode == "loopback" else (lambda ip: ip)
    os.makedirs(a.outdir, exist_ok=True)

    def dump(name, obj):
        with open(os.path.join(a.outdir, name + ".json"), "w") as f:
            json.dump(obj, f, indent=2)

    for k in range(1, 6):
        left_ip, right_ip = "10.0.%d.2" % k, "10.0.%d.1" % (k + 1)
        left_nh, right_nh = "10.0.%d.1" % k, "10.0.%d.2" % (k + 1)
        routes = []
        for s in range(1, 7):
            if s <= k:
                nh, bind = left_nh, left_ip
            else:
                nh, bind = right_nh, right_ip
            routes.append({"prefix": "10.0.%d.0/24" % s, "out_ip": u(nh), "out_port": PORT,
                           "local_bind_ip": u(bind), "local_bind_port": PORT})
        dump("r%d" % k, {
            "name": "r%d" % k,
            "local_ips": [left_ip, right_ip],
            "interfaces": [{"bind_ip": u(left_ip), "bind_port": PORT},
                           {"bind_ip": u(right_ip), "bind_port": PORT}],
            "routes": routes})

    dump("hostA", {"name": "hostA", "overlay_ip": "10.0.1.1", "bind_ip": u("10.0.1.1"),
                   "bind_port": PORT, "gateway_ip": u("10.0.1.2"), "gateway_port": PORT})
    dump("hostB", {"name": "hostB", "overlay_ip": "10.0.6.2", "bind_ip": u("10.0.6.2"),
                   "bind_port": PORT, "gateway_ip": u("10.0.6.1"), "gateway_port": PORT})
    print("wrote configs for mode=%s into %s/" % (a.mode, a.outdir))


if __name__ == "__main__":
    main()
