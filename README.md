# Software IPv4 Router over a UDP Overlay (CS3001 Project 14)

Owner of this code drop: **Nimra Mehmood (24K-0807)**
Covers: F1 (IPv4 + checksum), F2 (router loop), F3 (config + linear LPM), F4 (binary-trie LPM),
F6 (ping), F8 (raw-IP pcap), F10 lookup-scaling benchmark.
Left for Shorouq: F5 (ICMP errors), F7 (traceroute), F9 (tc netem/tbf), mesh links R1-R3 / R2-R4.

Topology: `hostA - r1 - r2 - r3 - r4 - r5 - hostB`, subnets `10.0.k.0/24` (k = 1..6).
Left node of a subnet is `.1`, right node is `.2`. Host A = `10.0.1.1`, Host B = `10.0.6.2`.
Each link is a pair of UDP sockets (port 5000); every datagram carries one raw IPv4 packet.

## Files
| File | Purpose |
|---|---|
| `ipv4.py` | F1: `compute_checksum`, `verify_checksum`, `build_ipv4`, `parse_ipv4`, `decrement_ttl` |
| `icmp.py` | ICMP echo build/parse + generic `build_icmp` (for F5 type 11 / type 3) |
| `routing_table.py` | F3 `lookup_linear`, F4 `BinaryTrie`, and `RoutingTable.lookup()` (switchable backend) |
| `pcap_logger.py` | F8: pcap writer, LINKTYPE_RAW (101) |
| `router.py` | F2: forwarding loop with Phase 2 hooks |
| `host_echo.py` | ICMP echo responder for Host B |
| `ping.py` | F6: overlay ping (RTT, loss, min/avg/max) |
| `gen_configs.py` | Generates `configs/*.json` (`--mode netns` or `--mode loopback`) |
| `setup_topology.sh` | `up` / `down` / `status` for the 7 namespaces + veth pairs |
| `run_routers.sh` | Starts/stops r1-r5 and the Host B responder inside their namespaces |
| `run_loopback_demo.sh` | No-root smoke test of the whole chain over 127.0.k.x |
| `pcap_check.py` | Offline pcap validator (checksum + TTL per packet) |
| `bench_lookup.py` | F10: linear vs trie scaling, 3 runs, mean/stdev -> `results/lookup_scaling.csv` |

## Run on Ubuntu 22.04 (namespaces)
```bash
sudo ./setup_topology.sh up                 # creates hostA, r1-r5, hostB (ip_forward=0)
sudo ./setup_topology.sh status
sudo ./run_routers.sh start linear          # or: start trie
sudo ip netns exec hostA python3 ping.py --config configs/hostA.json -c 5
#   expected: ttl=59 on every reply (64 - 5 routers), 0% loss
python3 pcap_check.py pcaps/r1.pcap pcaps/r2.pcap pcaps/r3.pcap pcaps/r4.pcap pcaps/r5.pcap
wireshark pcaps/r1.pcap                     # TTL 63 at r1 ... 59 at r5 for the request
sudo ./run_routers.sh stop
sudo ./setup_topology.sh down
```
Wireshark: Edit > Preferences > Protocols > IPv4 > enable "Validate the IPv4 checksum if possible".
Because the capture is LINKTYPE_RAW, Wireshark decodes IPv4 directly (no Ethernet header).

Optional: `sudo ip netns exec r3 tcpdump -ni v3r udp port 5000` to see the UDP encapsulation on the wire.

## Quick test without root
```bash
./run_loopback_demo.sh linear     # or trie
```

## Config format (`configs/rK.json`)
```json
{ "name": "r1",
  "local_ips": ["10.0.1.2", "10.0.2.1"],                  // router's own overlay IPs
  "interfaces": [{"bind_ip": "10.0.1.2", "bind_port": 5000}, ...],   // UDP sockets
  "routes": [{"prefix": "10.0.6.0/24", "out_ip": "10.0.2.2", "out_port": 5000,
              "local_bind_ip": "10.0.2.1", "local_bind_port": 5000}, ...] }
```
`prefix` is the overlay destination; `out_ip/out_port` is the next hop's UDP address;
`local_bind_*` selects which of the router's sockets sends the packet.

## Hooks for Phase 2 (Shorouq)
* `Router.lookup(dst_int)` -> `Route | None`; switch backend with `--lookup trie` (F4 is already implemented in `routing_table.py`; replace/extend if her version differs).
* `Router.on_ttl_expired(raw, ip, in_sock)` -> send ICMP Time Exceeded (type 11) to `ip["src"]`.
* `Router.on_no_route(raw, ip, in_sock)` -> send ICMP Destination Unreachable (type 3).
* `Router.on_local_delivery(...)` -> packets addressed to the router itself (needed for traceroute's final replies / pinging routers).
* `icmp.build_icmp(type, code, rest, body)`; ICMP error body = original IP header + first 8 bytes of payload. `ping.py` already prints received type 11 / type 3 messages.
* Mesh links: add routes + interfaces in `gen_configs.py` and `setup_topology.sh` (R1-R3, R2-R4).

## Handoff checklist
- [x] `setup_topology.sh up/down` for all 7 namespaces (needs a real Ubuntu VM with sudo)
- [x] ping Host A -> Host B, TTL arrives as 59
- [x] pcaps r1-r5: zero checksum errors, TTL drops by 1 per hop (verified on loopback with `pcap_check.py`)
- [x] hooks + README
