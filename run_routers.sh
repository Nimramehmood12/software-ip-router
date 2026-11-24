#!/usr/bin/env bash
# Start / stop the 5 routers + Host B echo responder inside their namespaces.
# Usage: sudo ./run_routers.sh start [linear|trie] | stop
# Then:  sudo ip netns exec hostA python3 ping.py --config configs/hostA.json -c 5
set -euo pipefail
cd "$(dirname "$0")"
PIDFILE=/tmp/swrouter.pids

start() {
  stop quiet
  python3 gen_configs.py --mode netns --outdir configs
  mkdir -p pcaps logs
  : > "$PIDFILE"
  for r in r1 r2 r3 r4 r5; do
    ip netns exec "$r" python3 router.py --config "configs/$r.json" \
        --pcap "pcaps/$r.pcap" --lookup "${1:-linear}" > "logs/$r.log" 2>&1 &
    echo $! >> "$PIDFILE"
  done
  ip netns exec hostB python3 host_echo.py --config configs/hostB.json > logs/hostB.log 2>&1 &
  echo $! >> "$PIDFILE"
  sleep 1
  echo "routers started (lookup=${1:-linear}); logs in logs/, pcaps in pcaps/"
}

stop() {
  if [[ -f "$PIDFILE" ]]; then
    while read -r p; do kill "$p" 2>/dev/null || true; done < "$PIDFILE"
    rm -f "$PIDFILE"
  fi
  [[ "${1:-}" == quiet ]] || echo "routers stopped"
}

case "${1:-}" in
  start) start "${2:-linear}" ;;
  stop) stop ;;
  *) echo "usage: sudo $0 start [linear|trie] | stop"; exit 1 ;;
esac
