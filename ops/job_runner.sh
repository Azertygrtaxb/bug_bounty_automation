#!/usr/bin/env bash
# job_runner.sh — exécute les travaux demandés depuis le board.
#
# Un runner par VPS, chacun sur SA phase :
#
#   VPS de reconnaissance :  job_runner.sh --phase recon --max-jobs 2
#   VPS de chasse         :  job_runner.sh --phase hunt  --max-jobs 3
#
# Il prend une ligne 'en_attente' dans bb_jobs, lance le script correspondant
# (recon.sh ou hunt.sh) et rend compte. Le board, lui, n'exécute jamais rien :
# il n'a ni docker.sock ni clé SSH — voir engine/db/013_ops_jobs.sql.
#
# CE SCRIPT EST LA SECONDE BARRIÈRE DE SÉCURITÉ. Le board valide déjà host et
# options en liste blanche (engine/ops.py), mais il écrit dans une base que
# d'autres processus peuvent atteindre. On re-valide donc TOUT ici, juste avant
# de construire la ligne de commande. Une valeur non reconnue fait échouer le
# job avec un message clair — elle n'est jamais « corrigée ».
#
# ARRÊT D'UN JOB : chaque job tourne dans son propre GROUPE DE PROCESSUS (setsid).
# recon.sh lance une dizaine de sous-processus en parallèle (ffuf, nuclei, katana…) ;
# tuer le seul PID du script laisserait tous ces outils continuer à marteler la
# cible, invisible depuis le board. On tue le groupe entier.

set -uo pipefail

VERSION="1.0"
SELF=$(readlink -f "${BASH_SOURCE[0]}")

# ─────────────────────────────────────────────────────────────── paramètres ──
PHASE=""
MAX_JOBS=2
POLL=8
PIPELINE="${BB_PIPELINE_DIR:-/opt/bb-pipeline}"
RUN_AS="${BB_RUN_AS:-bb}"
NAME=""
ONCE=false
SYNC_AFTER_RECON=true

DB_HOST="${BB_DB_HOST:-191.218.162.235}"
PG_CONTAINER="${BB_PG_CONTAINER:-bug_bounty_automation-postgres-1}"
PG_USER="${BB_PG_USER:-bbhunter}"
PG_DB="${BB_PG_DB:-bugbounty}"

RUNDIR="${BB_OPS_RUNDIR:-/run/bb-ops}"
LOGDIR="${BB_OPS_LOGDIR:-/var/log/bb-ops}"

EXEC_ID=""

usage() {
    sed -n '2,30p' "$0"
    cat <<'EOF'

Options :
  --phase <recon|hunt>   travaux que CE runner accepte           (obligatoire)
  --max-jobs <n>         jobs simultanés (défaut 2)
  --poll <s>             intervalle d'interrogation (défaut 8)
  --pipeline <dir>       racine de bb-pipeline (défaut /opt/bb-pipeline)
  --run-as <user>        compte qui exécute les scans (défaut bb)
  --name <nom>           identifiant du runner (défaut <hostname>-<phase>)
  --no-sync              ne pas pousser la recon vers le VPS de chasse après succès
  --once                 un seul tour de boucle puis sortie (test)
  --check                vérifie base + scripts + droits, puis sort
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --phase)     PHASE="$2"; shift 2 ;;
        --max-jobs)  MAX_JOBS="$2"; shift 2 ;;
        --poll)      POLL="$2"; shift 2 ;;
        --pipeline)  PIPELINE="$2"; shift 2 ;;
        --run-as)    RUN_AS="$2"; shift 2 ;;
        --name)      NAME="$2"; shift 2 ;;
        --no-sync)   SYNC_AFTER_RECON=false; shift ;;
        --once)      ONCE=true; shift ;;
        --check)     CHECK=true; shift ;;
        --executer)  EXEC_ID="$2"; shift 2 ;;   # interne : un job, dans son propre groupe
        -h|--help)   usage; exit 0 ;;
        *)           echo "option inconnue : $1" >&2; exit 2 ;;
    esac
done

[[ -n "$PHASE" || -n "$EXEC_ID" ]] || { usage; exit 2; }
[[ -z "$PHASE" || "$PHASE" == recon || "$PHASE" == hunt ]] \
    || { echo "phase invalide : $PHASE" >&2; exit 2; }
NAME="${NAME:-$(hostname)-${PHASE:-exec}}"

mkdir -p "$RUNDIR" "$LOGDIR" 2>/dev/null

ts()  { date +'%F %T'; }
log() { printf '%s [%s] %s\n' "$(ts)" "$NAME" "$*" >&2; }

# ───────────────────────────────────────────────────────────────── base ──
# La base n'écoute que sur le réseau Docker du VPS de chasse. En local on passe par
# `docker exec`, à distance par SSH. Le SQL voyage TOUJOURS sur stdin, jamais en
# argument de ssh : la commande distante est interprétée par le shell du compte
# distant (zsh ici), qui casse sur les parenthèses d'un « VALUES (...) ».
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=no
          -o ControlMaster=auto -o "ControlPath=$RUNDIR/ssh-%r@%h:%p" -o ControlPersist=10m)

if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$PG_CONTAINER"; then
    DB_MODE=local
else
    DB_MODE=ssh
fi

db() {
    # $1 = SQL. Sortie : lignes brutes, champs séparés par '|' (-qtA).
    if [[ "$DB_MODE" == local ]]; then
        printf '%s\n' "$1" | docker exec -i "$PG_CONTAINER" \
            psql -U "$PG_USER" -d "$PG_DB" -qtAX -v ON_ERROR_STOP=1 2>>"$LOGDIR/db.err"
    else
        printf '%s\n' "$1" | ssh "${SSH_OPTS[@]}" "root@$DB_HOST" \
            "docker exec -i $PG_CONTAINER psql -U $PG_USER -d $PG_DB -qtAX -v ON_ERROR_STOP=1" \
            2>>"$LOGDIR/db.err"
    fi
}

# Littéral SQL : double les apostrophes. Utilisé pour les seuls champs libres qu'on
# écrit (messages), jamais pour construire une commande.
q() { printf "'%s'" "${1//\'/\'\'}"; }

# ────────────────────────────────────────────────────────────── validation ──
# Reprend, en bash, exactement les règles de engine/ops.py. Si les deux divergent un
# jour, c'est CELLE-CI qui protège la machine.
valide_host() {
    [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]] \
        && (( ${#1} <= 253 ))
}
dans() { local x=$1; shift; for v in "$@"; do [[ "$x" == "$v" ]] && return 0; done; return 1; }
entier_entre() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= $2 && $1 <= $3 )); }

# L'index unique de bb_jobs empêche deux jobs simultanés sur la même cible, mais il ne
# voit RIEN de ce qui a été lancé à la main en SSH. Or les deux écrivent dans le même
# out/<host>/ : deux chasses s'écraseraient mutuellement journal.md et findings/, deux
# recons se corrompraient leurs artefacts. On regarde donc les processus réels.
deja_en_cours() {
    local phase=$1 host=$2
    case "$phase" in
        recon) pgrep -af 'recon\.sh'  2>/dev/null | grep -qF " $host" ;;
        hunt)  pgrep -af 'claude'     2>/dev/null | grep -qF "/out/$host" ;;
        *)     return 1 ;;
    esac
}

# ═════════════════════════════════════════════════ MODE EXÉCUTION D'UN JOB ══
# Lancé par la boucle via `setsid` : ce processus est chef de son groupe, donc $$
# vaut le PGID. On l'écrit en base AVANT de démarrer quoi que ce soit — sans lui,
# un job devenu incontrôlable ne pourrait plus être coupé depuis le board.
if [[ -n "$EXEC_ID" ]]; then
    PGID=$$
    NAME="job#$EXEC_ID"
    echo "$PGID" > "$RUNDIR/$EXEC_ID.pgid"
    db "UPDATE bb_jobs SET pgid = $PGID WHERE id = $EXEC_ID;" >/dev/null

    LIGNE=$(db "SELECT host || '|' || phase || '|' ||
                       coalesce(options->>'profile','') || '|' ||
                       coalesce(options->>'rate','') || '|' ||
                       coalesce(options->>'force','') || '|' ||
                       coalesce(options->>'model','') || '|' ||
                       coalesce(options->>'effort','') || '|' ||
                       coalesce(options->>'timeout_h','')
                FROM bb_jobs WHERE id = $EXEC_ID;" | head -1)
    IFS='|' read -r HOST JPHASE PROFILE RATE FORCE MODEL EFFORT TIMEOUT_H <<< "$LIGNE"

    finir() {
        local etat=$1 rc=$2 msg=$3
        db "UPDATE bb_jobs SET etat = $(q "$etat"), rc = ${rc:-NULL}, fin_le = now(),
                   message = $(q "$msg") WHERE id = $EXEC_ID;" >/dev/null
        rm -f "$RUNDIR/$EXEC_ID.pgid"
        exit "${rc:-0}"
    }

    valide_host "$HOST" || finir echec 2 "host refusé par le runner : $HOST"

    deja_en_cours "$JPHASE" "$HOST" && finir annule 0 \
        "un $JPHASE tourne déjà sur $HOST (lancé hors board) — non relancé"

    CMD=()
    case "$JPHASE" in
    recon)
        dans "$PROFILE" sweep deep long || finir echec 2 "profil refusé : $PROFILE"
        entier_entre "${RATE:-0}" 1 30   || finir echec 2 "rate hors bornes : $RATE"
        CMD=("$PIPELINE/bin/recon.sh" "$HOST" --profile "$PROFILE" --rate "$RATE")
        [[ "$FORCE" == "true" ]] && CMD+=(--force)
        ;;
    hunt)
        dans "$MODEL" opus sonnet fable                 || finir echec 2 "modèle refusé : $MODEL"
        dans "$EFFORT" low medium high xhigh max        || finir echec 2 "effort refusé : $EFFORT"
        entier_entre "${TIMEOUT_H:-0}" 1 8              || finir echec 2 "plafond refusé : $TIMEOUT_H"
        CMD=("$PIPELINE/bin/hunt.sh" "$HOST" --model "$MODEL" --effort "$EFFORT"
             --timeout "$TIMEOUT_H")
        ;;
    *)  finir echec 2 "phase inconnue : $JPHASE" ;;
    esac

    [[ -x "${CMD[0]}" ]] || finir echec 2 "script introuvable : ${CMD[0]}"

    # Le bouton stop envoie SIGTERM au GROUPE : recon.sh et tous ses outils le reçoivent
    # directement, on n'a pas à le repropager (le faire ici rebouclerait sur nous-mêmes).
    # Ce qui reste à faire, c'est enregistrer « annulé » et non « échec » : la distinction
    # décide si la cible mérite d'être relancée plus tard.
    trap 'trap - TERM INT; finir annule 143 "coupé depuis le board"' TERM INT

    # Compte dédié + shell de login : c'est ainsi que les scans tournent déjà à la main
    # (le PATH des outils Go vit dans le .profile de ce compte, pas dans celui de root).
    ARGS=$(printf '%q ' "${CMD[@]}")
    if [[ "$(id -un)" == "$RUN_AS" ]]; then
        ( cd "$PIPELINE" && bash -lc "$ARGS" ) &
    else
        ( cd "$PIPELINE" && sudo -u "$RUN_AS" -H bash -lc "$ARGS" ) &
    fi
    KID=$!
    wait "$KID"; RC=$?

    # La recon n'a de valeur que si elle atteint le VPS de chasse : sans cette poussée,
    # le bouton « chasse » resterait grisé et personne ne saurait pourquoi.
    SYNC=""
    if [[ "$JPHASE" == recon && $RC -eq 0 && "$SYNC_AFTER_RECON" == true
          && -x "$PIPELINE/bin/sync_to_hunt.sh" ]]; then
        if ( cd "$PIPELINE" && sudo -u "$RUN_AS" -H "$PIPELINE/bin/sync_to_hunt.sh" ) \
             >>"$LOGDIR/sync.log" 2>&1; then SYNC=" | synchro OK"; else SYNC=" | SYNCHRO ÉCHOUÉE"; fi
    fi

    case $RC in
        0)   finir termine 0   "terminé$SYNC" ;;
        124) finir termine 124 "coupé au plafond de temps$SYNC" ;;
        143|137) finir annule "$RC" "interrompu$SYNC" ;;
        *)   finir echec "$RC" "rc=$RC — voir $LOGDIR/$EXEC_ID.log$SYNC" ;;
    esac
fi

# ═══════════════════════════════════════════════════════ MODE BOUCLE (démon) ══
declare -A SLOTS=()          # id du job -> pid du processus setsid

hotes_prets_sql() {
    # Cibles dont la recon est complète SUR CETTE MACHINE. Le board s'en sert pour
    # savoir si une chasse est lançable — hunt.sh refuse sans marqueur DONE.
    local liste=() d
    for d in "$PIPELINE"/out/*/; do
        [[ -f "$d/DONE" ]] || continue
        local h; h=$(basename "$d")
        valide_host "$h" && liste+=("\"$h\"")
    done
    (( ${#liste[@]} )) && printf "'{%s}'" "$(IFS=,; echo "${liste[*]}")" || echo "'{}'"
}

# L'IP de sortie change à chaque rotation VPN, pas toutes les 8 secondes : la
# rafraîchir à chaque battement enverrait une requête sortante en continu, dans le
# tunnel, pour rien.
IP_CACHE="?"; IP_CACHE_T=0
ip_sortie() {
    local now; now=$(date +%s)
    if (( now - IP_CACHE_T > 300 )); then
        IP_CACHE=$(curl -s --max-time 6 https://ifconfig.io 2>/dev/null || echo "?")
        IP_CACHE_T=$now
    fi
    printf '%s' "$IP_CACHE"
}

battement() {
    local ip; ip=$(ip_sortie)
    db "INSERT INTO bb_runners (nom, phase, vu_le, jobs_max, jobs_actifs, ip_sortie,
                                version, hotes_prets)
        VALUES ($(q "$NAME"), $(q "$PHASE"), now(), $MAX_JOBS, ${#SLOTS[@]}, $(q "$ip"),
                $(q "$VERSION"), $(hotes_prets_sql)::text[])
        ON CONFLICT (nom) DO UPDATE SET vu_le = now(), phase = EXCLUDED.phase,
            jobs_max = EXCLUDED.jobs_max, jobs_actifs = EXCLUDED.jobs_actifs,
            ip_sortie = EXCLUDED.ip_sortie, version = EXCLUDED.version,
            hotes_prets = EXCLUDED.hotes_prets;" >/dev/null
}

# Au démarrage : des jobs peuvent être restés 'en_cours' après un redémarrage brutal.
# Sans ce ménage, l'index unique interdirait pour toujours de relancer ces cibles.
reprendre() {
    local id
    while read -r id; do
        [[ -n "$id" ]] || continue
        local pgid; pgid=$(cat "$RUNDIR/$id.pgid" 2>/dev/null)
        if [[ -n "$pgid" ]] && kill -0 "-$pgid" 2>/dev/null; then
            log "job #$id toujours vivant (pgid $pgid) — repris sous surveillance"
            SLOTS[$id]="$pgid"
        else
            log "job #$id était en cours mais son processus a disparu — marqué en échec"
            db "UPDATE bb_jobs SET etat='echec', fin_le=now(),
                       message=coalesce(message||' | ','')||'processus disparu (redémarrage ?)'
                WHERE id = $id;" >/dev/null
            rm -f "$RUNDIR/$id.pgid"
        fi
    done < <(db "SELECT id FROM bb_jobs WHERE etat='en_cours' AND runner=$(q "$NAME");")
}

moissonner() {
    local id pid
    for id in "${!SLOTS[@]}"; do
        pid="${SLOTS[$id]}"
        kill -0 "$pid" 2>/dev/null && continue
        unset "SLOTS[$id]"
        # L'exécutant met lui-même la ligne à jour ; s'il a été tué avant (SIGKILL),
        # personne ne l'a fait : on rattrape ici pour ne pas laisser un job fantôme.
        local etat; etat=$(db "SELECT etat FROM bb_jobs WHERE id = $id;" | head -1)
        if [[ "$etat" == "en_cours" ]]; then
            db "UPDATE bb_jobs SET etat='echec', rc=137, fin_le=now(),
                       message=coalesce(message||' | ','')||'tué sans rendre compte'
                WHERE id = $id;" >/dev/null
            log "job #$id disparu sans rendre compte — marqué en échec"
        else
            log "job #$id terminé ($etat)"
        fi
        rm -f "$RUNDIR/$id.pgid"
    done
}

arrets_demandes() {
    local id pgid
    while read -r id; do
        [[ -n "$id" && -n "${SLOTS[$id]:-}" ]] || continue
        pgid=$(cat "$RUNDIR/$id.pgid" 2>/dev/null) || continue
        [[ -n "$pgid" ]] || continue
        log "arrêt demandé pour #$id — SIGTERM au groupe $pgid"
        kill -TERM "-$pgid" 2>/dev/null
        # 15 s pour que les outils ferment leurs fichiers : un ffuf tué net perd tout
        # ce qu'il n'a pas encore écrit. Ensuite, SIGKILL sans discussion.
        ( sleep 15; kill -0 "-$pgid" 2>/dev/null && {
              kill -KILL "-$pgid" 2>/dev/null
              printf '%s [%s] #%s ne répondait pas — SIGKILL\n' "$(ts)" "$NAME" "$id" >&2; } ) &
    done < <(db "SELECT id FROM bb_jobs
                 WHERE etat='en_cours' AND stop_demande AND runner=$(q "$NAME");")
}

prendre_un_job() {
    # Verrou côté base : deux runners de la même phase ne peuvent pas prendre la même
    # ligne (FOR UPDATE SKIP LOCKED). L'interrupteur est relu ICI, à chaque tentative :
    # un « off » posé pendant un scan doit empêcher le SUIVANT de partir, tout de suite.
    local id
    id=$(db "UPDATE bb_jobs SET etat='en_cours', debut_le=now(), runner=$(q "$NAME")
             WHERE id = (SELECT j.id FROM bb_jobs j
                         WHERE j.phase = $(q "$PHASE") AND j.etat = 'en_attente'
                           AND EXISTS (SELECT 1 FROM bb_controle c
                                       WHERE c.cle = j.phase AND c.actif)
                         ORDER BY j.id FOR UPDATE SKIP LOCKED LIMIT 1)
             RETURNING id;" | head -1)
    [[ "$id" =~ ^[0-9]+$ ]] || return 1

    local host; host=$(db "SELECT host FROM bb_jobs WHERE id = $id;" | head -1)
    log "job #$id pris : $PHASE $host"
    # `setsid --wait` et pas `setsid` seul : le runner est chef de son propre groupe
    # (systemd), donc setsid FORKE. Sans --wait, $! serait le père éphémère, qui meurt
    # aussitôt — la boucle croirait le job terminé une seconde après l'avoir lancé.
    local sup=(--wait); setsid --help 2>&1 | grep -q -- --wait || sup=()
    setsid "${sup[@]}" "$SELF" --executer "$id" --pipeline "$PIPELINE" --run-as "$RUN_AS" \
        $( [[ "$SYNC_AFTER_RECON" == false ]] && echo --no-sync ) \
        >>"$LOGDIR/$id.log" 2>&1 &
    SLOTS[$id]=$!
    return 0
}

# ────────────────────────────────────────────────────────────────── contrôle ──
if [[ "${CHECK:-false}" == true ]]; then
    echo "runner        : $NAME (phase $PHASE, max $MAX_JOBS)"
    echo "base          : mode $DB_MODE  →  $(db "SELECT current_user || '@' || current_database();" | head -1)"
    echo "bb_jobs       : $(db "SELECT count(*) FROM bb_jobs;" | head -1) ligne(s)"
    echo "interrupteurs : $(db "SELECT string_agg(cle || '=' || actif, '  ') FROM bb_controle;" | head -1)"
    for s in recon.sh hunt.sh sync_to_hunt.sh; do
        [[ -x "$PIPELINE/bin/$s" ]] && echo "  ✓ $PIPELINE/bin/$s" || echo "  ✗ $PIPELINE/bin/$s ABSENT"
    done
    id -u "$RUN_AS" >/dev/null 2>&1 && echo "  ✓ compte $RUN_AS" || echo "  ✗ compte $RUN_AS inconnu"
    echo "recons prêtes : $(hotes_prets_sql)"
    exit 0
fi

trap 'log "arrêt du runner (les jobs en cours continuent)"; exit 0' TERM INT

log "démarré — phase=$PHASE max=$MAX_JOBS poll=${POLL}s base=$DB_MODE pipeline=$PIPELINE"
reprendre

while true; do
    moissonner
    arrets_demandes
    while (( ${#SLOTS[@]} < MAX_JOBS )); do prendre_un_job || break; done
    battement
    $ONCE && { log "mode --once : sortie"; exit 0; }
    sleep "$POLL"
done
