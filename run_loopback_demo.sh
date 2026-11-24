#!/usr/bin/env bash
# No-root smoke test: same code, same chain, but UDP over 127.0.k.x instead of netns.
# Usage: ./run_loopback_demo.sh [linear|trie]
set -euo pipefail
cd "$(dirname "$0")"
LOOKUP="${1:-linear}"
python3 gen_configs.py --mode loopback --outdir configs_loopback
mkdir -p pcaps logs
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT
for r in r1 r2 r3 r4 r5; do
  python3 router.py --config "configs_loopback/$r.json" --pcap "pcaps/$r.pcap" \
      --lookup "$LOOKUP" > "logs/$r.log" 2>&1 &
  PIDS+=($!)
done
python3 host_echo.py --config configs_loopback/hostB.json > logs/hostB.log 2>&1 &
PIDS+=($!)
sleep 1
python3 ping.py --config configs_loopback/hostA.json -c 5 -i 0.3
sleep 0.3
cleanup; trap - EXIT
echo; echo "--- pcap check ---"
python3 pcap_check.py pcaps/r1.pcap pcaps/r3.pcap pcaps/r5.pcap | grep -E "pcap v|packets,|#1 |#2 "
