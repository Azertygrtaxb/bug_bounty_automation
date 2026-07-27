#!/usr/bin/env bash
# Rotation d'IP IVPN — CALLABLE par le pipeline (rotate_egress() de ratelimit.py) OU
# par le cron filet-de-sécurité. Adapté de Rotator-v10.sh :
#   - IVPN_ACCOUNT_ID / POOL / TEST_URL lus depuis l'ENV (aucune valeur en dur) ;
#   - exposé comme rotation appelable (une rotation vers un pays FRAIS + vérif) ;
#   - bloc notify/Discord SUPPRIMÉ.
#
# Usage :
#   rotate-egress.sh                      # rote maintenant (déclenché par le pipeline)
#   rotate-egress.sh --if-blocked <URL>   # ne rote QUE si <URL> != 200 (cron filet)
set -euo pipefail

POOL="${POOL:-NL DE BE CH LU ES IT IE PT CZ FI BG GR HU SE IS HR DK AT NO GB PL RO RS SK UA IL US CA}"
TEST_URL="${ROTATION_TEST_URL:-https://ifconfig.io}"   # URL NEUTRE par défaut (jamais une cible)
MAX_TRIES="${MAX_TRIES:-15}"
TIMEOUT="${TIMEOUT:-15}"
UA="${UA:-Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0 Safari/537.36}"

read -r -a COUNTRIES <<<"$POOL"

probe() { curl -Ism "$TIMEOUT" -A "$UA" -o /dev/null -w '%{http_code}' "$1" || echo 000; }
exit_ip() { curl -s -m "$TIMEOUT" https://ifconfig.io || echo unknown; }

# Filet de sécurité (cron) : ne rien faire tant que la cible témoin répond 200.
if [[ "${1:-}" == "--if-blocked" ]]; then
  watch_url="${2:?--if-blocked requiert une URL}"
  [[ "$(probe "$watch_url")" == "200" ]] && { echo "ok ($watch_url=200) — pas de rotation"; exit 0; }
  echo "témoin $watch_url != 200 — rotation"
fi

ip_before="$(exit_ip)"
last=""
for ((i = 1; i <= MAX_TRIES; i++)); do
  C="${COUNTRIES[RANDOM % ${#COUNTRIES[@]}]}"
  [[ "$C" == "$last" ]] && continue
  last="$C"
  ivpn disconnect >/dev/null 2>&1 || true
  sleep 2
  if ivpn connect -fw_off -protocol OpenVPN -country_code -any "$C" >/dev/null 2>&1; then
    sleep 3
    if [[ "$(probe "$TEST_URL")" == "200" ]]; then
      ip_after="$(exit_ip)"
      echo "rotated country=$C ip_before=$ip_before ip_after=$ip_after http=200"
      [[ "$ip_after" != "$ip_before" && "$ip_after" != "unknown" ]] && exit 0
    fi
  fi
done
echo "rotate FAILED after $MAX_TRIES tries (last country=${last:-none})"
exit 1
