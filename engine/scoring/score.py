"""Worker de scoring : relit targets, applique les signaux de knowledge/ et le
gate, écrit score + score_raisons + le marquage scannable.

Aucun réseau, aucune IA — on ne fait que relire ce qui est déjà en base, y
compris body_hash/body_len et first_hop_* (démotion catch-all/erreur/canonique,
flag open redirect).
"""
import os
from collections import Counter, defaultdict

import psycopg
from psycopg.types.json import Json

from engine.celery_app import app
from engine.gate import gate
from knowledge import routage, semantique, signaux, substance

DATABASE_URL = os.environ["DATABASE_URL"]

_COLS = ("id, url, host, http_status, tech, tags, body_hash, body_len, "
         "first_hop_status, first_hop_location, body_text, response_headers, "
         "semantique_verdict")


def _target_dict(url, host, http_status, tech, tags, body_hash, body_len,
                 first_hop_status, first_hop_location, is_catchall, catchall_n,
                 body_text, response_headers):
    return {
        "url": url, "host": host, "http_status": http_status,
        "tech": tech or [], "tags": tags or {},
        "body_hash": body_hash, "body_len": body_len,
        "first_hop_status": first_hop_status, "first_hop_location": first_hop_location,
        "is_catchall": is_catchall, "catchall_n": catchall_n,
        "body_text": body_text, "response_headers": response_headers or {},
    }


def _est_redirection(first_hop_status):
    return first_hop_status is not None and 300 <= first_hop_status < 400


def _catchall_par_host(rows):
    """Fréquence des body_hash (corps SUBSTANTIELS) par host, en EXCLUANT les
    redirections : le corps d'un endpoint qui redirige est celui de sa CIBLE
    (souvent le même login), pas le sien — il ne doit pas polluer le catch-all.
    Renvoie {host: {hash_catchall: nb}}."""
    counts = defaultdict(Counter)
    for r in rows:
        host, body_hash, body_len, fh_status = r[2], r[6], r[7], r[8]
        if _est_redirection(fh_status):
            continue
        if body_hash and body_len is not None and body_len >= substance.CATCHALL_MIN_BODYLEN:
            counts[host][body_hash] += 1
    catchall = {}
    for host, c in counts.items():
        hashes = substance.catchall_hashes(c)
        if hashes:
            catchall[host] = {h: c[h] for h in hashes}
    return catchall


@app.task(name="score_targets")
def score_targets():
    """Score chaque ligne de targets + gate + démotion consciente de la réponse."""
    scored = 0
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT %s FROM targets" % _COLS)
            rows = cur.fetchall()

            catchall = _catchall_par_host(rows)  # {host: {hash: nb}}

            for (tid, url, host, http_status, tech, tags, body_hash, body_len,
                 fh_status, fh_location, body_text, response_headers,
                 sem_verdict) in rows:
                host_ca = catchall.get(host, {})
                is_ca = (body_hash in host_ca if body_hash
                         and not _est_redirection(fh_status) else False)
                target = _target_dict(url, host, http_status, tech, tags, body_hash,
                                      body_len, fh_status, fh_location, is_ca,
                                      host_ca.get(body_hash), body_text, response_headers)
                score, raisons = signaux.evaluer(target)
                # S0 : REPÊCHAGE sémantique (bonus borné) SUR le score déterministe, jamais
                # avant. Le déterministe reste le juge ; le sémantique sort le résidu de l'ombre.
                if sem_verdict:
                    score, rk = semantique.composer_priorite(score, sem_verdict)
                    if rk:
                        raisons = list(raisons) + [rk]
                # Brique B : PLAN de sondes ciblées (routage pur). Calculé APRÈS le repêchage
                # sémantique -> il voit le verdict ET les raisons déterministes finales.
                # convergence stricte : une famille n'est planifiée que si les deux convergent.
                # Vide si pas de verdict (sem non lancée) ou pas de convergence.
                plan = routage.plan(sem_verdict, raisons) if sem_verdict else []
                new_tags = {**(tags or {}),
                            "methode": "GET",
                            "scannable": gate.is_scannable(target)}
                cur.execute(
                    "UPDATE targets SET score = %s, score_raisons = %s::text[], "
                    "tags = %s::jsonb, sonde_plan = %s WHERE id = %s",
                    (score, raisons, Json(new_tags),
                     Json(plan) if plan else None, tid),
                )
                scored += 1
        conn.commit()
    return {"scored": scored}


@app.task(name="rebuild_leads")
def rebuild_leads(seuil=1):
    """Régénère la vue curée `leads` (source de vérité) après score_targets : applique
    la MÊME logique que engine/leads.py (1b scope + 1c collapse) et REMPLACE la table.
    targets (détail par endpoint) reste intacte."""
    from engine import leads
    lignes, st, remap = leads.construire(seuil)
    n = leads.persister(lignes, remap)
    return {"persistes": n, **st}
