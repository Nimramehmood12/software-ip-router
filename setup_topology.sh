#!/usr/bin/env bash
# Create / destroy / inspect the 7-namespace chain:
#   hostA - r1 - r2 - r3 - r4 - r5 - hostB      (subnets 10.0.1.0/24 ... 10.0.6.0/24)
# Usage: sudo ./setup_topology.sh up|down|status
set -euo pipefail

NODES=(hostA r1 r2 r3 r4 r5 hostB)
NLINKS=6

need_root() { [[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }; }

up() {
  need_root
  down quiet
  for ns in "${NODES[@]}"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
  done
  for ((i=1; i<=NLINKS; i++)); do
    left="${NODES[$((i-1))]}"; right="${NODES[$i]}"
    ip link add "v${i}l" type veth peer name "v${i}r"
    ip link set "v${i}l" netns "$left"
    ip link set "v${i}r" netns "$right"
    ip -n "$left"  addr add "10.0.${i}.1/24" dev "v${i}l"
    ip -n "$right" addr add "10.0.${i}.2/24" dev "v${i}r"
    ip -n "$left"  link set "v${i}l" up
    ip -n "$right" link set "v${i}r" up
  done
  # Only our Python processes may forward packets.
  for ns in "${NODES[@]}"; do
    ip netns exec "$ns" sysctl -q -w net.ipv4.ip_forward=0
  done
  echo "topology up: ${NODES[*]}"
}

down() {
  need_root
  for ns in "${NODES[@]}"; do ip netns del "$ns" 2>/dev/null || true; done   # deleting a ns removes its veths
  [[ "${1:-}" == quiet ]] || echo "topology down"
}

status() {
  for ns in "${NODES[@]}"; do
    echo "== $ns (ip_forward=$(ip netns exec "$ns" sysctl -n net.ipv4.ip_forward 2>/dev/null || echo '?'))"
    ip -n "$ns" -br addr 2>/dev/null | grep -v '^lo' || echo "  (missing)"
  done
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  *) echo "usage: sudo $0 up|down|status"; exit 1 ;;
esac
