"""Harnais S4.5 — MESURE (pas prod) : le MÊME échantillon jugé par plusieurs (modèle, effort),
puis TAUX D'ACCORD par fait et sur le VERDICT final. Sert à trancher "Sonnet 5 @ low suffit-il ?"
sur de la VRAIE data, au lieu de le supposer.

Propriétés :
  - LECTURE SEULE sur `targets` : n'écrit AUCUNE colonne semantique_* (ne pollue pas la prod).
  - Réutilise le juge aveugle de prod (même prompt, même schéma, même extrait) : ce qu'on
    mesure est bien le comportement réel, pas une variante.
  - Ignore le filtre `semantique_juge_le IS NULL` -> on peut rejouer le même échantillon.
  - Batch par config, réassociation par custom_id.

Usage (depuis la racine, worker/env avec ANTHROPIC_API_KEY + DATABASE_URL) :
  python -m engine.semantique_bench --n 60
  python -m engine.semantique_bench --n 60 --configs "claude-sonnet-5:low,claude-sonnet-5:medium"

La 1re config listée est la RÉFÉRENCE ; l'accord des autres est mesuré CONTRE elle.
Défaut : sonnet-5:low (candidat) vs sonnet-5:medium (filet qualité).
"""
import os
import sys
import time
from collections import Counter

import psycopg

from knowledge import config
from engine import semantique_run as sr
from knowledge import semantique

DATABASE_URL = os.environ["DATABASE_URL"]
FAITS = list(sr.SCHEMA_FAITS["required"])
# Les verdicts qui font REMONTER un lead : un désaccord ici coûte plus qu'ailleurs.
VERDICTS_QUI_COMPTENT = ("applicatif", "surface_auth")


def _echantillon(n):
    """Le résidu (comme la prod) MAIS sans le filtre 'non déjà jugé' -> rejouable."""
    with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, body_text, response_headers, url, first_hop_location, score "
            "FROM targets WHERE body_text IS NOT NULL AND length(body_text) > 0 "
            "AND score BETWEEN 0 AND %s AND http_status BETWEEN 200 AND 403 "
            "ORDER BY score DESC LIMIT %s", (config.SEUIL_RESIDU, n))
        out = []
        for tid, body, headers, url, fhl, score in cur.fetchall():
            if sr._est_asset(url):
                continue
            if sr.sonde.est_content_type_asset(sr._content_type(headers)):
                continue
            out.append({"id": tid, "body": body, "headers": headers, "url": url})
        return out


def _juger_batch(cands, modele, effort):
    """Renvoie {id: (faits|None, verdict)} pour une config. Aucune écriture DB."""
    from anthropic import Anthropic
    from anthropic.types.messages.batch_create_params import Request
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
    client = Anthropic()

    oc = {"format": {"type": "json_schema", "schema": sr.SCHEMA_FAITS}}
    if sr._supporte_effort(modele):
        oc["effort"] = effort

    reqs = []
    for c in cands:
        params = MessageCreateParamsNonStreaming(
            model=modele, max_tokens=2048,
            system=[{"type": "text", "text": sr.SYSTEME_JUGE,
                     "cache_control": {"type": "ephemeral"}}],
            output_config=oc,
            messages=[{"role": "user",
                       "content": sr.extrait_aveugle(c["body"], c["headers"])}])
        reqs.append(Request(custom_id=str(c["id"]), params=params))

    batch = client.messages.batches.create(requests=reqs)
    while client.messages.batches.retrieve(batch.id).processing_status != "ended":
        time.sleep(int(os.environ.get("SEM_POLL_SECONDES", "15")))

    res = {}
    for r in client.messages.batches.results(batch.id):
        tid = int(r.custom_id)
        if r.result.type != "succeeded":
            res[tid] = (None, "ERREUR")
            continue
        faits = sr._faits_de_message(r.result.message)
        verdict = semantique.decider(faits)[0] if faits else "ERREUR"
        res[tid] = (faits, verdict)
    return res


def _accord(ref, autre, ids):
    """Compare 'autre' à 'ref' : accord par fait + accord verdict + désaccords qui comptent."""
    n = len(ids)
    par_fait = {f: 0 for f in FAITS}
    verdict_ok = 0
    desaccords_qui_comptent = []
    for tid in ids:
        rf, rv = ref[tid]
        af, av = autre[tid]
        if rf and af:
            for f in FAITS:
                if rf.get(f) == af.get(f):
                    par_fait[f] += 1
        if rv == av:
            verdict_ok += 1
        elif rv in VERDICTS_QUI_COMPTENT or av in VERDICTS_QUI_COMPTENT:
            desaccords_qui_comptent.append((tid, rv, av))
    return {"n": n, "verdict_ok": verdict_ok,
            "par_fait": {f: par_fait[f] for f in FAITS},
            "desaccords_qui_comptent": desaccords_qui_comptent}


def _pct(x, n):
    return "%5.1f%%" % (100.0 * x / n) if n else "  n/a"


def main(argv):
    n = 40
    configs = [("claude-sonnet-5", "low"), ("claude-sonnet-5", "medium")]
    if "--n" in argv:
        n = int(argv[argv.index("--n") + 1])
    if "--configs" in argv:
        spec = argv[argv.index("--configs") + 1]
        configs = [tuple(p.split(":", 1)) for p in spec.split(",") if ":" in p]

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY absente — le bench appelle l'API, la clé est obligatoire.")
        return 1

    cands = _echantillon(n)
    if not cands:
        print("Aucun candidat dans le résidu (score 0..%d). Lance un rush d'abord." % config.SEUIL_RESIDU)
        return 1
    ids = [c["id"] for c in cands]
    print("=== BENCH S4.5 | %d endpoints du résidu | %d configs ===" % (len(ids), len(configs)))

    resultats = {}
    for (modele, effort) in configs:
        print("-> juge %s @ %s …" % (modele, effort))
        resultats[(modele, effort)] = _juger_batch(cands, modele, effort)

    ref_cfg = configs[0]
    ref = resultats[ref_cfg]
    print("\nRÉFÉRENCE : %s @ %s" % ref_cfg)
    print("distribution des verdicts (référence) : %s"
          % dict(Counter(v for _, v in ref.values())))

    for cfg in configs[1:]:
        a = _accord(ref, resultats[cfg], ids)
        print("\n--- %s @ %s  VS référence ---" % cfg)
        print("  accord VERDICT final : %s (%d/%d)"
              % (_pct(a["verdict_ok"], a["n"]), a["verdict_ok"], a["n"]))
        print("  accord par fait :")
        for f in FAITS:
            print("     %-16s %s" % (f, _pct(a["par_fait"][f], a["n"])))
        dqc = a["desaccords_qui_comptent"]
        print("  désaccords sur un verdict QUI COMPTE (applicatif/surface_auth) : %d" % len(dqc))
        for tid, rv, av in dqc[:15]:
            print("     id=%-8d ref=%-14s autre=%s" % (tid, rv, av))
        if len(dqc) > 15:
            print("     … (+%d)" % (len(dqc) - 15))

    print("\nLECTURE : si l'accord verdict est haut ET peu de désaccords 'qui comptent',")
    print("la config la moins chère (référence) suffit. Sinon, garde la config plus forte.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
