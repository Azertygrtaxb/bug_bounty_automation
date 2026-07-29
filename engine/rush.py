"""Orchestrateur RUSH — recon TIÉRÉE pour rendre 48k traitable.

  TIER 1 (shallow) sur TOUS les hosts  ->  RANK  ->  TIER 2 (deep) sur le TOP borné.

Les deux tiers passent par la concurrence Celery bornée + le rate-limiter central
(admission host/filiale/global). Le deep est plafonné (MAX_DEEP_HOSTS) et traité dans
l'ordre du rang (le meilleur d'abord). Lecture seule côté orchestrateur.

Usage :
    python engine/rush.py host1 host2 ...
    python engine/rush.py --file hosts.txt
"""
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

import psycopg  # noqa: E402
from engine import scope  # noqa: E402
from engine.celery_app import app  # noqa: E402
from engine.recon.discover import MAX_DEEP_HOSTS  # noqa: E402
from knowledge import config  # noqa: E402

DB = os.environ["DATABASE_URL"]


def _hosts_from_argv(argv):
    if argv and argv[0] == "--file":
        return [l.strip() for l in Path(argv[1]).read_text().splitlines() if l.strip()]
    return [a.strip().lower() for a in argv if a.strip()]


def _fmt_duree(s):
    if s == float("inf"):
        return "∞"
    s = int(s)
    h, r = divmod(s, 3600)
    m, sec = divmod(r, 60)
    return "%dh%02dm" % (h, m) if h else ("%dm%02ds" % (m, sec) if m else "%ds" % sec)


def _assurer_avancement(cur):
    cur.execute("CREATE TABLE IF NOT EXISTS rush_avancement ("
                "host TEXT PRIMARY KEY, phase TEXT, fini_le TIMESTAMPTZ DEFAULT now())")


def _marquer_avances(hosts, phase):
    """A4 — enregistre les hosts terminés (host, phase). PK=host : la dernière phase
    écrase (shallow -> deep)."""
    if not hosts:
        return
    with psycopg.connect(DB) as c, c.cursor() as cur:
        _assurer_avancement(cur)
        cur.executemany("INSERT INTO rush_avancement(host, phase, fini_le) VALUES (%s,%s,now()) "
                        "ON CONFLICT (host) DO UPDATE SET phase=EXCLUDED.phase, fini_le=now()",
                        [(h, phase) for h in hosts])
        c.commit()


def _hosts_avances(phase=None):
    """Hosts déjà marqués (tous si phase=None ; sinon exactement cette phase)."""
    with psycopg.connect(DB) as c, c.cursor() as cur:
        _assurer_avancement(cur)
        if phase is None:
            cur.execute("SELECT host FROM rush_avancement")
        else:
            cur.execute("SELECT host FROM rush_avancement WHERE phase = %s", (phase,))
        return {r[0] for r in cur.fetchall()}


def _wait_all(taches, label, phase=None, continuer_si_incomplet=False, poll=5):
    """Attend TOUTES les tâches. `taches` = liste de (host, AsyncResult). R1 timeout adapté
    (max(TIMEOUT_MIN, n·TIMEOUT_PAR_TACHE)). R2 lève à l'expiration (tier partiel = FAUX)
    sauf --continuer-si-incomplet. R3 progression toutes les PROGRESS_SECS. A4 : chaque host
    terminé est marqué `phase` en base AU FIL de l'attente (reprise possible après crash)."""
    n = len(taches)
    if n == 0:
        return 0.0
    timeout = max(config.TIMEOUT_MIN, n * config.TIMEOUT_PAR_TACHE)
    print("[%s] attente de %d tâches | timeout %s = max(%ds, %d×%ds)"
          % (label, n, _fmt_duree(timeout), config.TIMEOUT_MIN, n, config.TIMEOUT_PAR_TACHE))
    t0 = time.time()
    prochain = config.PROGRESS_SECS
    vus = set()                                   # hosts déjà marqués (évite les doublons)
    while True:
        prets = [(h, r) for (h, r) in taches if r.ready()]
        neufs = [h for (h, r) in prets if h not in vus]
        if neufs and phase:
            _marquer_avances(neufs, phase)        # A4 : progrès persisté au fil de l'eau
            vus.update(neufs)
        if len(prets) >= n:
            break
        ecoule = time.time() - t0
        if ecoule >= prochain:
            prochain += config.PROGRESS_SECS
            debit = len(prets) / ecoule if ecoule > 0 else 0.0
            eta = (n - len(prets)) / debit if debit > 0 else float("inf")
            print("[%s] %d/%d terminés | %s écoulées | %.2f tâches/s | ETA %s"
                  % (label, len(prets), n, _fmt_duree(ecoule), debit, _fmt_duree(eta)))
        if ecoule >= timeout:
            reste = n - len(prets)
            msg = ("[%s] TIMEOUT %s atteint : %d/%d tâches NON terminées. Un classement sur "
                   "un tier partiel est FAUX. Augmente TIMEOUT_PAR_TACHE, relance avec "
                   "--reprendre, ou passe --continuer-si-incomplet en connaissance de cause."
                   % (label, _fmt_duree(timeout), reste, n))
            if continuer_si_incomplet:
                sys.stderr.write("AVERTISSEMENT — " + msg + "\n")
                break
            raise RuntimeError(msg)
        time.sleep(poll)
    dt = time.time() - t0
    ok = sum(1 for (h, r) in taches if r.successful())
    print("[%s] %d/%d réussis en %s" % (label, ok, n, _fmt_duree(dt)))
    return dt


def _compter_targets():
    with psycopg.connect(DB) as c, c.cursor() as cur:
        cur.execute("SELECT count(*) FROM targets")
        return cur.fetchone()[0]


def _attendre_agregation(res, label, n_lignes, poll=5):
    """A1 — attend une tâche d'agrégation (score_targets/rebuild_leads) avec un timeout
    DÉRIVÉ du parc (plancher + terme ∝ lignes de targets) + progression. À l'expiration :
    message explicite nommant l'étape (pas de trace Celery brute)."""
    timeout = config.TIMEOUT_AGREGATION_MIN + (n_lignes // 1000) * config.TIMEOUT_AGREGATION_PAR_1000
    print("[%s] agrégation | timeout %s = %ds + %d×%ds/1000 (sur %d lignes)"
          % (label, _fmt_duree(timeout), config.TIMEOUT_AGREGATION_MIN,
             n_lignes // 1000, config.TIMEOUT_AGREGATION_PAR_1000, n_lignes))
    t0 = time.time()
    prochain = config.PROGRESS_SECS
    while not res.ready():
        ecoule = time.time() - t0
        if ecoule >= prochain:
            prochain += config.PROGRESS_SECS
            print("[%s] en cours depuis %s… (timeout %s)"
                  % (label, _fmt_duree(ecoule), _fmt_duree(timeout)))
        if ecoule >= timeout:
            raise RuntimeError("[%s] TIMEOUT %s : l'étape d'agrégation n'a pas fini. "
                               "Augmente TIMEOUT_AGREGATION_* ou relance avec --reprendre."
                               % (label, _fmt_duree(timeout)))
        time.sleep(poll)
    return res.get(timeout=30)


_PATHS_CAP = 30   # échantillon de paths/host suffisant pour deep_rank (SPA/nom)


def _ancetres_lances(host, lances):
    """Les hosts de la LISTE LANCÉE qui sont `host` lui-même ou un de ses domaines PARENTS
    (a.b.exemple.fr -> a.b.exemple.fr, b.exemple.fr, exemple.fr ; jamais le TLD nu)."""
    labels = (host or "").split(".")
    res = []
    for i in range(len(labels) - 1):       # s'arrête avant le dernier label (pas de TLD nu)
        cand = ".".join(labels[i:])
        if cand in lances:
            res.append(cand)
    return res


def _rank(hosts):
    """(live triés par DEEP_RANK desc, dead). A2 : SÉMANTIQUE PAR HOST restaurée SANS revenir
    aux 48 414 requêtes. Une seule passe streaming ; chaque ligne est attribuée à TOUS ses
    ancêtres présents dans la liste lancée (a.exemple.fr et b.exemple.fr restent DISTINCTS ;
    exemple.fr, s'il est lancé, agrège les deux). O(lignes × labels), mémoire O(#hosts lancés)."""
    lances = set(hosts)
    agg = {h: {"smax": -1, "tech": set(), "paths": [], "nb": 0} for h in hosts}
    with psycopg.connect(DB) as c:
        with c.cursor(name="rank_scan") as cur:            # curseur serveur = stream
            cur.itersize = 5000
            cur.execute("SELECT host, score, tech, url FROM targets")
            for host, score, tech, url in cur:
                for anc in _ancetres_lances(host, lances):
                    g = agg[anc]
                    g["nb"] += 1
                    sc = score or 0
                    if sc > g["smax"]:
                        g["smax"] = sc
                    for t in (tech or []):
                        g["tech"].add(t)
                    if url and len(g["paths"]) < _PATHS_CAP:
                        g["paths"].append(url)
    live, dead = [], []
    for h in hosts:
        g = agg[h]
        if g["nb"] == 0:
            dead.append({"host": h})
            continue
        dr, detail = config.deep_rank(g["smax"], sorted(g["tech"]), h, g["paths"])
        live.append({"host": h, "deep_rank": dr, "detail": detail, "surface": g["nb"]})
    live.sort(key=lambda x: (x["deep_rank"], x["surface"]), reverse=True)
    return live, dead


def _ecrire_listes(dead, live, deep, ecartes):
    """A3 — listes COMPLÈTES dans un fichier horodaté (un journal de 40k lignes à l'écran
    n'est pas exploitable). Renvoie le chemin."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    chemin = "/app/rush_%s.txt" % stamp
    try:
        with open(chemin, "w", encoding="utf-8") as fh:
            fh.write("# RUSH %s — listes complètes\n\n" % stamp)
            fh.write("## MORTS (%d)\n" % len(dead))
            for d in dead:
                fh.write(d["host"] + "\n")
            fh.write("\n## VIVANTS RANKÉS (%d) — host  deep_rank  sh spa prod nom core  surface\n" % len(live))
            for x in live:
                d = x["detail"]
                fh.write("%s\t%d\t%d %d %d %d %d\t%d\n" % (
                    x["host"], d["deep_rank"], d["score_shallow"], d["bonus_spa"],
                    d["bonus_produit"], d["bonus_nom"], d["bonus_core"], x["surface"]))
            fh.write("\n## DEEP SÉLECTIONNÉS (%d)\n" % len(deep))
            for h in deep:
                fh.write(h + "\n")
            fh.write("\n## ÉCARTÉS (%d)\n" % len(ecartes))
            for h in ecartes:
                fh.write(h + "\n")
        return chemin
    except OSError as e:
        sys.stderr.write("[rush] impossible d'écrire %s : %s\n" % (chemin, e))
        return None


def main(argv):
    # R2 : un tier partiel FAIT ÉCHOUER le rush ; --continuer-si-incomplet force la suite.
    # A4 : --reprendre saute les hosts déjà traités (le tier 1 n'est pas refait).
    continuer = "--continuer-si-incomplet" in argv
    reprendre = "--reprendre" in argv
    argv = [a for a in argv if a not in ("--continuer-si-incomplet", "--reprendre")]
    hosts = _hosts_from_argv(argv)
    if not hosts:
        print("usage: python engine/rush.py host1 ... | --file hosts.txt "
              "[--reprendre] [--continuer-si-incomplet]")
        return 1

    roots = scope.deriver_roots(hosts)
    scope.enregistrer_roots(roots)
    print("=== RUSH tiéré sur %d hosts | SCOPE_ROOTS=%d (%s) | MAX_DEEP_HOSTS=%d%s ==="
          % (len(hosts), len(roots), ",".join(roots[:6]) + ("…" if len(roots) > 6 else ""),
             MAX_DEEP_HOSTS, " | --reprendre" if reprendre else ""))

    try:
        # --- TIER 1 : SHALLOW (saute les hosts déjà faits si --reprendre) ---
        hosts_shallow = hosts
        if reprendre:
            deja = _hosts_avances() & set(hosts)
            hosts_shallow = [h for h in hosts if h not in deja]
            print("--reprendre : %d hosts déjà traités (shallow), %d restants"
                  % (len(deja), len(hosts_shallow)))
        sh = [(h, app.send_task("discover_shallow", args=[h])) for h in hosts_shallow]
        t_shallow = _wait_all(sh, "TIER1 shallow", phase="shallow", continuer_si_incomplet=continuer)

        # --- Agrégation (timeouts A1 dérivés du parc) ---
        n_lignes = _compter_targets()
        _attendre_agregation(app.send_task("score_targets"), "score_targets", n_lignes)
        _attendre_agregation(app.send_task("rebuild_leads"), "rebuild_leads", n_lignes)

        # --- Classement (A2 : une requête) + promotion DEEP ---
        live, dead = _rank(hosts)
        deep_all = [x["host"] for x in live if x["deep_rank"] > 0][:MAX_DEEP_HOSTS]
        ecartes = [x["host"] for x in live if x["host"] not in deep_all]

        # A3 : sortie BORNÉE à l'écran, listes complètes -> fichier.
        fichier = _ecrire_listes(dead, live, deep_all, ecartes)
        print("\n--- CLASSEMENT (top %d / %d vivants ; %d morts) ---"
              % (min(config.AFFICHAGE_RANG_MAX, len(live)), len(live), len(dead)))
        print("   %-52s %5s = %4s +%3s +%3s +%3s +%3s" % ("host", "RANG", "sh", "spa", "prod", "nom", "core"))
        for x in live[:config.AFFICHAGE_RANG_MAX]:
            d = x["detail"]
            print("   %-52s %5d = %4d +%3d +%3d +%3d +%3d"
                  % (x["host"][:52], d["deep_rank"], d["score_shallow"], d["bonus_spa"],
                     d["bonus_produit"], d["bonus_nom"], d["bonus_core"]))
        if fichier:
            print("   (listes complètes morts/vivants/deep/écartés -> %s)" % fichier)

        # --- TIER 2 : DEEP (saute les deep déjà faits si --reprendre) ---
        deep = deep_all
        if reprendre:
            deja_deep = _hosts_avances("deep") & set(deep_all)
            deep = [h for h in deep_all if h not in deja_deep]
            print("--reprendre : %d deep déjà faits, %d restants" % (len(deja_deep), len(deep)))
        dp = [(h, app.send_task("discover_deep", args=[h])) for h in deep]
        t_deep = _wait_all(dp, "TIER2 deep", phase="deep", continuer_si_incomplet=continuer)

        pr = [(h, app.send_task("probe_idor_candidates", args=[h])) for h in deep]
        _wait_all(pr, "TIER2 sonde", phase="sonde", continuer_si_incomplet=continuer)
    except Exception as e:
        sys.stderr.write("\n[rush] ÉCHEC : %s\n-> RELANCE la MÊME commande avec --reprendre : "
                         "les hosts déjà traités seront sautés (le tier 1 ne sera PAS refait).\n" % e)
        return 2

    print("\n=== MÉTRIQUES BRUTES ===")
    print("hosts totaux   : %d | morts : %d | vivants : %d | deep-traités : %d (plafond %d)"
          % (len(hosts), len(dead), len(live), len(deep), MAX_DEEP_HOSTS))
    print("temps TIER1 : %s | TIER2 deep : %s" % (_fmt_duree(t_shallow), _fmt_duree(t_deep)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
