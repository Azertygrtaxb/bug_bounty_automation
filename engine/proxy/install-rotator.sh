#!/usr/bin/env bash
# Installe IVPN + le cron filet-de-sécurité de rotation. Adapté de
# installing-rotatorV3.sh :
#   - IVPN_ACCOUNT_ID lu depuis l'ENV (PLUS de valeur en dur) ;
#   - IVPN install + login + cron (filet de sécurité) conservés ;
#   - provider-config Discord + notify ENTIÈREMENT SUPPRIMÉS (webhook retiré du code).
#
# À lancer sur l'HÔTE de recon (là où IVPN est machine-wide). Charge d'abord l'env :
#   set -a; . .env; set +a; sudo -E bash engine/proxy/install-rotator.sh
set -euo pipefail

: "${IVPN_ACCOUNT_ID:?IVPN_ACCOUNT_ID doit venir de lenv gitignore - aucun secret en dur}"

apt-get update -y
apt-get install -y curl ca-certificates gpg apt-transport-https

# --- Install IVPN CLI (Ubuntu/Debian) ---
curl -fsSL https://repo.ivpn.net/stable/ubuntu/generic.gpg | gpg --dearmor >/usr/share/keyrings/ivpn-archive-keyring.gpg
curl -fsSL https://repo.ivpn.net/stable/ubuntu/generic.list | tee /etc/apt/sources.list.d/ivpn.list >/dev/null
chmod 644 /usr/share/keyrings/ivpn-archive-keyring.gpg /etc/apt/sources.list.d/ivpn.list
apt-get update -y
apt-get install -y ivpn

# --- Script de rotation (callable + filet) ---
SRC="$(dirname "$(readlink -f "$0")")/rotate-egress.sh"
install -m 0755 "$SRC" /usr/local/bin/rotate-egress.sh

# --- Cron FILET DE SÉCURITÉ : rote seulement si le témoin groupebpce != 200 ---
# (Le déclencheur PRIMAIRE est désormais le signal WAF du crawl réel, côté pipeline.)
cat >/etc/cron.d/ivpn-rotate <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
*/15 * * * * root ROTATION_TEST_URL=https://ifconfig.io /usr/local/bin/rotate-egress.sh --if-blocked https://www.groupebpce.com/ >>/var/log/ivpn-rotate.log 2>&1
EOF
chmod 644 /etc/cron.d/ivpn-rotate

# --- IVPN login depuis l'env ---
ivpn login "${IVPN_ACCOUNT_ID}" || echo "ℹ️  login IVPN à refaire : ivpn login \$IVPN_ACCOUNT_ID"

echo "✅ IVPN installé, rotate-egress.sh en place, cron filet actif. AUCUN secret en dur, AUCUN Discord."
