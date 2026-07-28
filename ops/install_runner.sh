#!/usr/bin/env bash
# install_runner.sh — installe le runner de travaux sur un VPS.
#
#   VPS de reconnaissance :  sudo ./ops/install_runner.sh recon
#   VPS de chasse         :  sudo ./ops/install_runner.sh hunt
#
# Idempotent : relancer après un `git pull` met simplement le script à jour.
# Ne DÉMARRE pas le service (voir la fin) — on veut vérifier `--check` d'abord.

set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "à lancer en root" >&2; exit 1; }

PHASE="${1:-}"
[[ "$PHASE" == recon || "$PHASE" == hunt ]] || { echo "usage: $0 <recon|hunt>" >&2; exit 2; }

SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEST=/opt/bb-ops

ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!\033[0m %s\n' "$*"; }

install -d -m 0755 "$DEST" /var/log/bb-ops /run/bb-ops
install -m 0755 "$SRC/job_runner.sh" "$DEST/job_runner.sh"
ok "runner installé dans $DEST"

install -m 0644 "$SRC/bb-job-runner@.service" /etc/systemd/system/bb-job-runner@.service

# /run est un tmpfs : sans ce fichier, le répertoire des pgid disparaît au reboot et
# les jobs survivants deviendraient impossibles à retrouver.
printf 'd /run/bb-ops 0755 root root -\n' > /etc/tmpfiles.d/bb-ops.conf
systemd-tmpfiles --create /etc/tmpfiles.d/bb-ops.conf >/dev/null 2>&1

CONF="/etc/default/bb-job-runner-$PHASE"
if [[ ! -f "$CONF" ]]; then
    if [[ "$PHASE" == recon ]]; then
        cat > "$CONF" <<'EOF'
# Reconnaissance : deux scans en parallèle au maximum. Ils partagent la MÊME IP de
# sortie, donc leurs débits s'additionnent — trois scans à 12 req/s font 36 req/s vus
# de la cible, alors que chacun se croit sage.
BB_MAX_JOBS=2
BB_POLL=8
BB_PIPELINE_DIR=/opt/bb-pipeline
BB_RUN_AS=bb
# Base : elle vit sur le VPS de chasse, on y accède par SSH (clé déjà en place
# pour la synchro rsync).
BB_DB_HOST=191.218.162.235
EOF
    else
        cat > "$CONF" <<'EOF'
# Chasse : les sessions Claude sont surtout gourmandes en mémoire. Au-delà de trois
# simultanées, l'OOM killer commence à en abattre — et une session tuée à mi-parcours
# ne laisse que son journal.
BB_MAX_JOBS=3
BB_POLL=8
BB_PIPELINE_DIR=/opt/bb-pipeline
BB_RUN_AS=bb
EOF
    fi
    ok "configuration créée : $CONF"
else
    ok "configuration conservée : $CONF"
fi

systemctl daemon-reload
ok "unité systemd bb-job-runner@$PHASE prête"

[[ -x /opt/bb-pipeline/bin/recon.sh ]] || warn "/opt/bb-pipeline/bin/recon.sh absent — le runner refusera les jobs"

cat <<EOF

Vérifier AVANT de démarrer :
  $DEST/job_runner.sh --phase $PHASE --check

Puis :
  systemctl enable --now bb-job-runner@$PHASE
  journalctl -u bb-job-runner@$PHASE -f
EOF
