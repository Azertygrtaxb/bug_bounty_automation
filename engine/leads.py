"""VUE LEADS — leads propres et lisibles (export CSV / rapport / dashboard).

N'AGIT PAS sur le scoring : la base garde le détail complet. Cette vue applique, à la
LECTURE :
  1b — EXCLUT les leads hors-cible (rebond sur un domaine hors périmètre in-scope,
       config §14) sauf INCLURE_HORS_CIBLE.
  1c — COLLAPSE les quasi-doublons : un même PATTERN normalisé (id/UUID/ObjectId/
       opaque -> {id}, année -> {annee}, valeurs de params-id -> {id}) + les frères à
       préfixe commun (>= COLLAPSE_PREFIXE_MIN segments finaux non-id qui varient ->
       {*}) => UN représentant (score max) + un compteur `nb`.

Le pattern normalisé est stocké (tags.lead_pattern) pour que le dashboard groupe pareil.

La vue est PERSISTÉE dans la table `leads` (source de vérité) : construire() calcule,
persister() remplace tout, lire() relit sans recalcul. La tâche Celery rebuild_leads
(engine/scoring/score.py) la régénère après chaque score_targets. targets reste le
détail par endpoint ; leads = la vue curée.

Usage :  python engine/leads.py [seuil] [--rebuild] [--csv fichier]
    --rebuild : recalcule (1b+1c) et remplace la table leads (sinon lit la table).
"""
import os
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psycopg  # noqa: E402

from engine import scope  # noqa: E402
from knowledge import config, harvest  # noqa: E402
from knowledge.signaux import _ID_PARAM_KEYS, _est_annee_chemin  # noqa: E402

DATABASE_URL = os.environ["DATABASE_URL"]
_ID_KEYS = _ID_PARAM_KEYS


def _seg_token(seg):
    if not seg:
        return seg
    if _est_annee_chemin(seg):
        return "{annee}"
    sh = harvest.shape_of(seg)
    if sh and sh[0] in ("num", "uuid", "objectid", "opaque"):
        return "{id}"
    return seg


def patternize(url):
    """URL -> PATTERN normalisé (segments id -> {id}/{annee}, valeurs params-id -> {id})."""
    p = urlsplit(url)
    path = "/".join(_seg_token(s) for s in p.path.split("/"))
    parts = []
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        kl = k.lower()
        if v and (kl in _ID_KEYS or kl.endswith("_id") or kl == "id"):
            parts.append("%s={id}" % k)
        elif _est_annee_chemin(v):
            parts.append("%s={annee}" % k)
        elif v:
            parts.append("%s=%s" % (k, v))
        else:
            parts.append("%s=" % k)
    return path + ("?" + "&".join(parts) if parts else "")


def _collapse_freres(patterns_par_host):
    """Frères à préfixe commun : si >= N patterns d'un host partagent un préfixe et ne
    diffèrent que par un segment final NON-id -> préfixe/{*}. Renvoie {(host,pat): pat2}."""
    remap = {}
    pref = defaultdict(set)
    for host, pat in patterns_par_host:
        if "?" in pat:
            continue
        segs = pat.rstrip("/").split("/")
        if len(segs) < 2:
            continue
        last = segs[-1]
        if not last or last in ("{id}", "{annee}", "{*}"):
            continue
        pref[(host, "/".join(segs[:-1]))].add(pat)
    for (host, prefixe), pats in pref.items():
        if len(pats) >= config.COLLAPSE_PREFIXE_MIN:
            for p in pats:
                remap[(host, p)] = prefixe + "/{*}"
    return remap


def _assurer_table(cur):
    """CREATE TABLE IF NOT EXISTS leads (idempotent, aligné sur db/006_leads.sql)."""
    cur.execute(
        "CREATE TABLE IF NOT EXISTS leads ("
        " host TEXT NOT NULL, pattern TEXT NOT NULL, url_representative TEXT,"
        " score INTEGER, raisons TEXT[], nb INTEGER, http_status INTEGER,"
        " tech TEXT[], in_scope BOOLEAN, updated_at TIMESTAMPTZ DEFAULT now(),"
        " PRIMARY KEY (host, pattern))")


def construire(seuil=1):
    """Calcule les leads curés (1b scope + 1c collapse). Renvoie (lignes, stats).
    Chaque ligne = {host, pattern, url_representative, score, raisons, nb, http_status,
    tech, in_scope} (le représentant = le membre au score MAX du groupe). Écrit aussi
    tags.lead_pattern sur targets (groupement dashboard). N'ÉCRIT PAS dans `leads` :
    c'est persister() qui le fait (séparation calcul / écriture)."""
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, host, url, score, COALESCE(score_raisons,'{}'), "
                        "http_status, COALESCE(tech,'{}'), COALESCE(tags,'{}') "
                        "FROM targets WHERE score >= %s", (seuil,))
            rows = cur.fetchall()

            brut = len(rows)
            # 1b — exclusion HORS-SCOPE : registered-domain ∉ SCOPE_ROOTS dérivé de la
            # liste lancée (OU marque hors_cible si présente). Scope vide -> fail-open.
            roots = scope.charger_roots()
            gardes, exclus_hc = [], 0
            for rid, host, url, score, raisons, http_status, tech, tags in rows:
                marque = "hors_cible_de_lancement" in ",".join(raisons)
                dehors = scope.hors_scope(host, roots) or marque
                if not config.INCLURE_HORS_SCOPE and dehors:
                    exclus_hc += 1
                    continue
                gardes.append({"id": rid, "host": host, "url": url, "score": score,
                               "raisons": list(raisons or []), "http_status": http_status,
                               "tech": list(tech or []), "tags": tags,
                               "in_scope": not dehors})
            apres_1b = len(gardes)

            # 1c — patternize + stockage tags.lead_pattern
            for g in gardes:
                pat = patternize(g["url"])
                g["pattern"] = pat
                if (g["tags"] or {}).get("lead_pattern") != pat:
                    cur.execute("UPDATE targets SET tags = jsonb_set(COALESCE(tags,'{}'::jsonb), "
                                "'{lead_pattern}', to_jsonb(%s::text)) WHERE id = %s", (pat, g["id"]))
            # collapse des frères à préfixe commun
            remap = _collapse_freres({(g["host"], g["pattern"]) for g in gardes})
            groupes = {}  # (host, pattern_final) -> {nb, score_max, representant}
            for g in gardes:
                pat = remap.get((g["host"], g["pattern"]), g["pattern"])
                key = (g["host"], pat)
                grp = groupes.setdefault(key, {"nb": 0, "score": -1, "rep": None})
                grp["nb"] += 1
                if g["score"] > grp["score"]:
                    grp["score"] = g["score"]; grp["rep"] = g
        conn.commit()

    lignes = []
    for (host, pat), grp in groupes.items():
        rep = grp["rep"]
        lignes.append({"host": host, "pattern": pat, "url_representative": rep["url"],
                       "score": grp["score"], "raisons": rep["raisons"], "nb": grp["nb"],
                       "http_status": rep["http_status"], "tech": rep["tech"],
                       "in_scope": rep["in_scope"]})
    lignes.sort(key=lambda x: (x["score"], x["nb"]), reverse=True)
    return lignes, {"brut": brut, "apres_1b": apres_1b, "exclus_hors_cible": exclus_hc,
                    "apres_1c": len(lignes)}


def persister(lignes):
    """Remplace TOUT le contenu de `leads` par `lignes` (source de vérité régénérée à
    chaque re-score : les patterns disparus d'un run précédent ne survivent pas)."""
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            _assurer_table(cur)
            cur.execute("TRUNCATE leads")
            cur.executemany(
                "INSERT INTO leads (host, pattern, url_representative, score, raisons, "
                "nb, http_status, tech, in_scope, updated_at) VALUES "
                "(%(host)s, %(pattern)s, %(url_representative)s, %(score)s, %(raisons)s, "
                "%(nb)s, %(http_status)s, %(tech)s, %(in_scope)s, now())", lignes)
        conn.commit()
    return len(lignes)


def lire(seuil=1):
    """Lit `leads` (la source de vérité) — AUCUN recalcul. Base de l'export/dashboard."""
    with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
        _assurer_table(cur)
        cur.execute("SELECT host, pattern, url_representative, score, raisons, nb, "
                    "http_status, tech, in_scope FROM leads WHERE score >= %s "
                    "ORDER BY score DESC, nb DESC", (seuil,))
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


def main(argv):
    seuil = next((int(a) for a in argv if a.isdigit()), 1)
    if "--rebuild" in argv:  # recalcule (1b+1c) et remplace la table
        lignes, st = construire(seuil)
        n = persister(lignes)
        print("=== REBUILD leads (seuil>=%d) : brut %d -> 1b %d (hors-scope exclus %d) "
              "-> 1c %d => %d persistés ===" % (seuil, st["brut"], st["apres_1b"],
                                                st["exclus_hors_cible"], st["apres_1c"], n))

    # AFFICHAGE + EXPORT : lecture depuis la table `leads`, pas de recalcul.
    lignes = lire(seuil)
    print("%-5s %-4s %-40s %s" % ("score", "nb", "host", "pattern"))
    for r in lignes[:40]:
        print("%-5d %-4d %-40s %s" % (r["score"], r["nb"], r["host"][:40], r["pattern"][:80]))
    if "--csv" in argv:
        chemin = argv[argv.index("--csv") + 1]
        import csv as _csv
        with open(chemin, "w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh)
            w.writerow(["score", "nb", "host", "pattern", "url_representative",
                        "http_status", "in_scope", "raisons"])
            for r in lignes:
                w.writerow([r["score"], r["nb"], r["host"], r["pattern"],
                            r["url_representative"], r["http_status"], r["in_scope"],
                            ",".join(r["raisons"] or [])])
        print("CSV (depuis la table leads) -> %s (%d lignes)" % (chemin, len(lignes)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
