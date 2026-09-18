#!/usr/bin/env bash
set -uo pipefail
cd /home/bug_bounty_automation
LOG=/root/rush.log
CHUNK_SIZE="${CHUNK_SIZE:-500}"     # hosts/tranche (= fréquence de rotation)
ROTATE="${ROTATE:-1}"

vps_ip(){ curl -s https://api.ipify.org; }
worker_ip(){ docker compose exec -T worker python -c "import urllib.request;print(urllib.request.urlopen('https://api.ipify.org').read().decode())" 2>/dev/null; }

check_leak(){
  local w h; w="$(worker_ip)"; h="$(vps_ip)"
  echo "  worker=$w  vps=$h" | tee -a "$LOG"
  if [ -z "$w" ] || [ "$w" = "$h" ]; then echo "  ❌ FUITE/VPN down — STOP" | tee -a "$LOG"; return 1; fi
  echo "  ✅ egress VPN ok" | tee -a "$LOG"
}

wait_gluetun(){
  for i in $(seq 1 25); do
    [ "$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q gluetun)" 2>/dev/null)" = healthy ] && return 0
    sleep 3
  done; return 1
}

rotate(){
  echo "[$(date +%H:%M:%S)] rotation IP…" | tee -a "$LOG"
  docker compose up -d --force-recreate gluetun worker >/dev/null 2>&1
  wait_gluetun && echo "  nouvelle IP: $(worker_ip)" | tee -a "$LOG"
}

case "${1:-}" in
  up)
    docker compose up -d --build; wait_gluetun; check_leak ;;
  run)
    LIST="${2:?usage: rush.sh run <liste>}"
    check_leak || exit 1
    echo "=== RUSH $(wc -l < "$LIST") hosts, tranches de $CHUNK_SIZE ===" | tee -a "$LOG"
    rm -f /tmp/rush_chunk_*; split -l "$CHUNK_SIZE" "$LIST" /tmp/rush_chunk_
    for chunk in /tmp/rush_chunk_*; do
      [ "$ROTATE" = 1 ] && { rotate; check_leak || { echo "leak après rotation, STOP"|tee -a "$LOG"; exit 1; }; }
      echo "[$(date +%H:%M:%S)] tranche $chunk ($(wc -l < "$chunk"))" | tee -a "$LOG"
      docker compose cp "$chunk" worker:/tmp/chunk.txt
      docker compose exec -T worker python engine/rush.py --file /tmp/chunk.txt 2>&1 | tee -a "$LOG" || echo "  (tranche errée, on continue)" | tee -a "$LOG"
    done
    echo "=== RUSH terminé ===" | tee -a "$LOG" ;;
  status)
    echo "worker=$(worker_ip)  vps=$(vps_ip)"
    docker compose exec -T postgres psql -U bbhunter -d bugbounty -tc "SELECT count(*) FROM targets WHERE score>0;" | xargs echo "leads (score>0):" ;;
  stop) docker compose stop worker; echo "worker stoppé" ;;
  *) echo "usage: rush.sh {up|run <liste>|status|stop}" ;;
esac
