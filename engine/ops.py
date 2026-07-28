"""OPS (Tier 5) — pilotage des lancements depuis le board : file `bb_jobs`, interrupteur
`bb_controle`, présence des runners `bb_runners`.

Le board n'exécute RIEN. Il écrit une demande ; le runner de la machine concernée
(engine/../ops/job_runner.sh) la prend, lance `recon.sh` ou `hunt.sh` sur l'hôte, et
rend compte. Voir engine/db/013_ops_jobs.sql pour le pourquoi de ce découpage.

CE FICHIER EST LA FRONTIÈRE DE SÉCURITÉ. Tout ce qui sort d'ici finit en argument d'une
commande shell sur un VPS. Rien n'est accepté qui ne soit explicitement listé :
  - le host doit valider un motif de nom de domaine strict ;
  - chaque option est soit dans une liste blanche de valeurs, soit un entier borné.
Une valeur non reconnue est REJETÉE (ValueError), jamais « nettoyée » : un filtrage qui
transforme laisse toujours un cas non prévu passer, un filtrage qui refuse, non.

Usage CLI (diagnostic) :  python engine/ops.py [etat|purge-fantomes]
"""
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psycopg  # noqa: E402

DATABASE_URL = os.environ["DATABASE_URL"]

PHASES = ("recon", "hunt")
ETATS_VIVANTS = ("en_attente", "en_cours")

# Nom de domaine : minuscules, au moins un point, longueur totale bornée. Volontairement
# plus strict que la RFC (pas d'underscore, pas de majuscule) — les cibles viennent de
# `targets`, qui est déjà normalisée.
_RE_HOST = re.compile(
    r"^(?=.{4,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")

# Liste blanche des options, par phase. (type, valeurs autorisées | bornes).
_OPTIONS = {
    "recon": {
        "profile": ("choix", ("sweep", "deep", "long")),
        "rate":    ("entier", 1, 30),
        "force":   ("bool", None),
    },
    "hunt": {
        "model":     ("choix", ("opus", "sonnet", "fable")),
        "effort":    ("choix", ("low", "medium", "high", "xhigh", "max")),
        "timeout_h": ("entier", 1, 8),
    },
}

DEFAUTS = {
    "recon": {"profile": "deep", "rate": 12, "force": False},
    "hunt":  {"model": "opus", "effort": "high", "timeout_h": 4},
}


def valider_host(host):
    h = (host or "").strip().lower()
    if not _RE_HOST.match(h):
        raise ValueError("host invalide : %r" % (host,))
    return h


def valider_options(phase, brut):
    """Options reçues du navigateur -> dict sûr. Toute clé inconnue est IGNORÉE, toute
    valeur hors liste blanche fait échouer la demande."""
    if phase not in PHASES:
        raise ValueError("phase inconnue : %r" % (phase,))
    schema = _OPTIONS[phase]
    out = dict(DEFAUTS[phase])
    for cle, val in (brut or {}).items():
        if cle not in schema:
            continue                       # clé inconnue : silencieusement écartée
        genre = schema[cle][0]
        if genre == "choix":
            if val not in schema[cle][1]:
                raise ValueError("valeur refusée pour %s : %r" % (cle, val))
            out[cle] = val
        elif genre == "entier":
            try:
                n = int(val)
            except (TypeError, ValueError):
                raise ValueError("%s doit être un entier" % cle)
            lo, hi = schema[cle][1], schema[cle][2]
            if not (lo <= n <= hi):
                raise ValueError("%s hors bornes (%d..%d)" % (cle, lo, hi))
            out[cle] = n
        elif genre == "bool":
            out[cle] = bool(val) and val not in ("0", "false", "False")
    return out


def _co():
    return psycopg.connect(DATABASE_URL)


# ─────────────────────────────────────────────────────────────────── demandes ──
def lancer(host, phase, par, options=None):
    """Met un job en file. Lève ValueError si la cible a déjà un job vivant pour cette
    phase — deux recons du même host écriraient dans le même répertoire."""
    host = valider_host(host)
    opts = valider_options(phase, options)
    with _co() as c, c.cursor() as cur:
        cur.execute("SELECT actif FROM bb_controle WHERE cle = %s", (phase,))
        r = cur.fetchone()
        arrete = r is not None and not r[0]
        try:
            cur.execute(
                """INSERT INTO bb_jobs (host, phase, options, demande_par)
                   VALUES (%s, %s, %s::jsonb, %s) RETURNING id, demande_le""",
                (host, phase, json.dumps(opts), par))
        except psycopg.errors.UniqueViolation:
            raise ValueError("%s a déjà un %s en attente ou en cours" % (host, phase))
        jid, quand = cur.fetchone()
    return {"id": jid, "host": host, "phase": phase, "options": opts,
            "demande_le": quand,
            # Le job est bien en file, mais personne ne le prendra tant que
            # l'interrupteur est sur off : il faut le dire, pas le laisser deviner.
            "avertissement": ("interrupteur %s sur OFF — le job attendra" % phase)
                             if arrete else None}


def arreter(job_id, par):
    """Demande l'arrêt d'UN job. En attente -> annulé tout de suite. En cours -> pose le
    drapeau ; c'est le runner qui tue le groupe de processus (lui seul sait où il est)."""
    with _co() as c, c.cursor() as cur:
        cur.execute("SELECT etat FROM bb_jobs WHERE id = %s", (job_id,))
        r = cur.fetchone()
        if not r:
            raise ValueError("job %s introuvable" % job_id)
        if r[0] == "en_attente":
            cur.execute("""UPDATE bb_jobs SET etat = 'annule', fin_le = now(),
                           message = %s WHERE id = %s AND etat = 'en_attente'""",
                        ("annulé avant démarrage par %s" % par, job_id))
            return {"id": job_id, "etat": "annule"}
        if r[0] == "en_cours":
            cur.execute("""UPDATE bb_jobs SET stop_demande = true,
                           message = %s WHERE id = %s""",
                        ("arrêt demandé par %s" % par, job_id))
            return {"id": job_id, "etat": "arret_demande"}
        return {"id": job_id, "etat": r[0], "message": "déjà terminé"}


def tout_couper(par):
    """Le grand coup de frein : interrupteurs sur off ET arrêt demandé sur tout ce qui
    tourne ou attend. Sert quand l'IP se fait bannir ou qu'il faut rendre la main à la
    cible immédiatement."""
    with _co() as c, c.cursor() as cur:
        cur.execute("UPDATE bb_controle SET actif = false, maj_le = now(), maj_par = %s",
                    (par,))
        cur.execute("""UPDATE bb_jobs SET etat = 'annule', fin_le = now(), message = %s
                       WHERE etat = 'en_attente'""", ("coupure globale par %s" % par,))
        annules = cur.rowcount
        cur.execute("""UPDATE bb_jobs SET stop_demande = true, message = %s
                       WHERE etat = 'en_cours' AND NOT stop_demande""",
                    ("coupure globale par %s" % par,))
        coupes = cur.rowcount
    return {"annules": annules, "arrets_demandes": coupes}


def controle(cle, actif, par):
    if cle not in PHASES:
        raise ValueError("interrupteur inconnu : %r" % (cle,))
    with _co() as c, c.cursor() as cur:
        cur.execute("""INSERT INTO bb_controle (cle, actif, maj_le, maj_par)
                       VALUES (%s, %s, now(), %s)
                       ON CONFLICT (cle) DO UPDATE
                       SET actif = EXCLUDED.actif, maj_le = now(), maj_par = EXCLUDED.maj_par""",
                    (cle, bool(actif), par))
    return {"cle": cle, "actif": bool(actif)}


# ─────────────────────────────────────────────────────────────────── lectures ──
def _lignes(cur):
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def etat(limite=60):
    """Tout ce que la page de statut affiche, en UNE requête aller-retour : elle
    rafraîchit toutes les quelques secondes, un appel par bloc multiplierait la charge
    sans rien apporter."""
    with _co() as c, c.cursor() as cur:
        cur.execute("SELECT cle, actif, maj_le, maj_par FROM bb_controle ORDER BY cle")
        ctrl = {r["cle"]: r for r in _lignes(cur)}

        cur.execute("""SELECT nom, phase, vu_le, jobs_max, jobs_actifs, ip_sortie, version,
                              EXTRACT(EPOCH FROM (now() - vu_le))::int AS age_s,
                              coalesce(array_length(hotes_prets, 1), 0) AS nb_prets
                       FROM bb_runners ORDER BY phase, nom""")
        runners = _lignes(cur)

        # Les vivants d'abord (ce qui tourne, ce qui attend), puis l'historique récent.
        cur.execute("""SELECT id, host, phase, etat, options, demande_par, demande_le,
                              debut_le, fin_le, runner, pgid, rc, message, stop_demande,
                              EXTRACT(EPOCH FROM (now() - coalesce(debut_le, demande_le)))::int AS age_s
                       FROM bb_jobs
                       WHERE etat IN ('en_attente', 'en_cours')
                       ORDER BY etat DESC, id""")
        vivants = _lignes(cur)

        cur.execute("""SELECT id, host, phase, etat, options, demande_par, demande_le,
                              debut_le, fin_le, runner, rc, message,
                              EXTRACT(EPOCH FROM (fin_le - debut_le))::int AS duree_s
                       FROM bb_jobs
                       WHERE etat NOT IN ('en_attente', 'en_cours')
                       ORDER BY coalesce(fin_le, demande_le) DESC LIMIT %s""", (limite,))
        historique = _lignes(cur)
    return {"controle": ctrl, "runners": runners, "vivants": vivants,
            "historique": historique}


def etat_hosts(hosts):
    """Pour une poignée de hosts affichés : où en sont recon et chasse, et un job est-il
    déjà en file ? C'est ce qui permet au bouton d'afficher « recon faite le … » plutôt
    que d'inviter à relancer un scan qui vient d'être joué."""
    hosts = [h for h in {(h or "").strip().lower() for h in (hosts or [])} if h]
    if not hosts:
        return {}
    out = {h: {"host": h} for h in hosts}
    with _co() as c, c.cursor() as cur:
        # bb_pipeline_status existe seulement si le pipeline a été installé.
        cur.execute("SELECT to_regclass('public.bb_pipeline_status') IS NOT NULL")
        if cur.fetchone()[0]:
            cur.execute("""SELECT host, recon_le, recon_statut, urls, hunt_le, hunt_statut,
                                  findings
                           FROM bb_pipeline_status WHERE host = ANY(%s)""", (hosts,))
            for r in _lignes(cur):
                out.setdefault(r["host"], {"host": r["host"]}).update(r)
        cur.execute("""SELECT host, phase, etat, id FROM bb_jobs
                       WHERE host = ANY(%s) AND etat IN ('en_attente', 'en_cours')""",
                    (hosts,))
        for r in _lignes(cur):
            out.setdefault(r["host"], {"host": r["host"]})["job_%s" % r["phase"]] = {
                "id": r["id"], "etat": r["etat"]}
        # Une chasse n'est lançable que si la recon est arrivée sur le VPS de chasse.
        cur.execute("""SELECT unnest(hotes_prets) FROM bb_runners WHERE phase = 'hunt'""")
        for (h,) in cur.fetchall():
            if h in out:
                out[h]["recon_disponible"] = True
    return out


def purger_fantomes(age_min=15):
    """Jobs 'en_cours' dont le runner ne donne plus signe de vie depuis `age_min` minutes :
    la machine a redémarré, ou le runner a été tué. Sans ce ménage, l'index unique
    interdirait pour toujours de relancer cette cible."""
    age_min = max(2, int(age_min))
    with _co() as c, c.cursor() as cur:
        cur.execute("""UPDATE bb_jobs j SET etat = 'echec', fin_le = now(),
                         message = coalesce(j.message || ' | ', '')
                                   || 'runner muet depuis plus de ' || %s
                                   || ' min — job présumé mort'
                       WHERE j.etat = 'en_cours'
                         AND NOT EXISTS (SELECT 1 FROM bb_runners r
                                         WHERE r.nom = j.runner
                                           AND r.vu_le > now() - make_interval(mins => %s))
                       RETURNING id, host, phase""", (age_min, age_min))
        return _lignes(cur)


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "etat"
    if action == "purge-fantomes":
        for r in purger_fantomes():
            print("fantôme purgé : #%(id)s %(phase)s %(host)s" % r)
    else:
        e = etat()
        print("interrupteurs :", {k: v["actif"] for k, v in e["controle"].items()})
        for r in e["runners"]:
            print("  runner %-28s %-6s vu il y a %4ss  %s/%s job(s)"
                  % (r["nom"], r["phase"], r["age_s"], r["jobs_actifs"], r["jobs_max"]))
        for j in e["vivants"]:
            print("  #%-5s %-8s %-40s %s" % (j["id"], j["phase"], j["host"], j["etat"]))
