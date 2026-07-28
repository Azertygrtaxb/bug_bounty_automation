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

Usage :  python engine/leads.py [seuil_score]   (défaut 1)  [--csv fichier]
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


def construire(seuil=1):
    """Renvoie (lignes_leads, stats). Applique 1b puis 1c. Écrit tags.lead_pattern."""
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, host, url, score, COALESCE(score_raisons,'{}'), "
                        "COALESCE(tags,'{}') FROM targets WHERE score >= %s", (seuil,))
            rows = cur.fetchall()

            brut = len(rows)
            # 1b — exclusion HORS-SCOPE : registered-domain ∉ SCOPE_ROOTS dérivé de la
            # liste lancée (OU marque hors_cible si présente). Scope vide -> fail-open.
            roots = scope.charger_roots()
            gardes, exclus_hc = [], 0
            for rid, host, url, score, raisons, tags in rows:
                marque = "hors_cible_de_lancement" in ",".join(raisons)
                if not config.INCLURE_HORS_SCOPE and (scope.hors_scope(host, roots) or marque):
                    exclus_hc += 1
                    continue
                gardes.append((rid, host, url, score, tags))
            apres_1b = len(gardes)

            # 1c — patternize + stockage tags.lead_pattern
            pat_of = {}
            for rid, host, url, score, tags in gardes:
                pat = patternize(url)
                pat_of[rid] = (host, pat)
                if (tags or {}).get("lead_pattern") != pat:
                    cur.execute("UPDATE targets SET tags = jsonb_set(COALESCE(tags,'{}'::jsonb), "
                                "'{lead_pattern}', to_jsonb(%s::text)) WHERE id = %s", (pat, rid))
            # collapse des frères à préfixe commun
            remap = _collapse_freres(set(pat_of.values()))
            groupes = {}  # (host, pattern_final) -> {nb, score_max, exemple}
            for rid, host, url, score, tags in gardes:
                host2, pat = pat_of[rid]
                pat = remap.get((host, pat), pat)
                key = (host, pat)
                g = groupes.setdefault(key, {"nb": 0, "score": 0, "exemple": url})
                g["nb"] += 1
                if score > g["score"]:
                    g["score"] = score; g["exemple"] = url
        conn.commit()

    lignes = [{"host": h, "pattern": p, "nb": g["nb"], "score": g["score"], "exemple": g["exemple"]}
              for (h, p), g in groupes.items()]
    lignes.sort(key=lambda x: (x["score"], x["nb"]), reverse=True)
    return lignes, {"brut": brut, "apres_1b": apres_1b, "exclus_hors_cible": exclus_hc,
                    "apres_1c": len(lignes)}


def main(argv):
    seuil = int(argv[0]) if argv and argv[0].isdigit() else 1
    lignes, st = construire(seuil)
    print("=== LEADS (seuil score>=%d) : brut %d -> 1b %d (hors-cible exclus %d) -> 1c %d ==="
          % (seuil, st["brut"], st["apres_1b"], st["exclus_hors_cible"], st["apres_1c"]))
    print("%-5s %-4s %-40s %s" % ("score", "nb", "host", "pattern"))
    for r in lignes[:40]:
        print("%-5d %-4d %-40s %s" % (r["score"], r["nb"], r["host"][:40], r["pattern"][:80]))
    csv = None
    if "--csv" in argv:
        csv = argv[argv.index("--csv") + 1]
        import csv as _csv
        with open(csv, "w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh); w.writerow(["score", "nb", "host", "pattern", "exemple"])
            for r in lignes:
                w.writerow([r["score"], r["nb"], r["host"], r["pattern"], r["exemple"]])
        print("CSV -> %s (%d lignes)" % (csv, len(lignes)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
