"""Worker de scoring : relit targets, applique les signaux de knowledge/ et le
gate, écrit score + score_raisons + le marquage scannable.

Aucun réseau, aucune IA — on ne fait que relire ce qui est déjà en base, y
compris body_hash/body_len et first_hop_* (démotion catch-all/erreur/canonique,
flag open redirect).
"""
import os
from collections import defaultdict

import psycopg
from psycopg.types.json import Json

from engine.celery_app import app
from engine.gate import gate
from knowledge import routage, semantique, signaux, substance

DATABASE_URL = os.environ["DATABASE_URL"]
SCORE_FETCH_BATCH = 750

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


def _lots(cur, taille=SCORE_FETCH_BATCH):
    """Itère un curseur par lots bornés ; aucun `fetchall()` des corps HTTP."""
    while True:
        rows = cur.fetchmany(taille)
        if not rows:
            return
        yield rows


def _charger_catchall(cur):
    """Calcule les catch-all côté PostgreSQL et ne rapatrie que les hash qualifiés.

    La formule est strictement celle de `substance.catchall_hashes`, en excluant les
    redirections. Le trafic Python est donc proportionnel aux catch-all, pas aux corps.
    """
    cur.execute(
        "WITH body_counts AS ("
        " SELECT host, body_hash, count(*)::bigint AS n"
        " FROM targets WHERE body_hash IS NOT NULL AND body_len >= %s"
        " AND (first_hop_status IS NULL OR first_hop_status < 300"
        "      OR first_hop_status >= 400)"
        " GROUP BY host, body_hash"
        "), qualifies AS ("
        " SELECT host, body_hash, n, sum(n) OVER (PARTITION BY host) AS total"
        " FROM body_counts"
        ") SELECT host, body_hash, n FROM qualifies"
        " WHERE n >= %s OR n::numeric / NULLIF(total, 0) >= %s",
        (substance.CATCHALL_MIN_BODYLEN, substance.CATCHALL_MIN_ENDPOINTS,
         substance.CATCHALL_MIN_RATIO),
    )
    catchall = defaultdict(dict)
    for rows in _lots(cur):
        for host, body_hash, n in rows:
            catchall[host][body_hash] = n
    return dict(catchall)


_UPDATE_TARGET = (
    "UPDATE targets SET score = %s, score_raisons = %s::text[], "
    "tags = %s::jsonb, sonde_plan = %s WHERE id = %s"
)


def _scorer_targets():
    """Score atomiquement avec un curseur serveur et des lots de 750 lignes."""
    scored = 0
    conn = psycopg.connect(DATABASE_URL)
    try:
        with conn.cursor() as aggregate_cur:
            catchall = _charger_catchall(aggregate_cur)

        # Curseur nommé = portail PostgreSQL : `body_text` n'est jamais matérialisé en
        # entier dans le processus. Les UPDATE utilisent un second curseur, même transaction.
        with conn.cursor(name="score_targets_stream") as read_cur:
            read_cur.itersize = SCORE_FETCH_BATCH
            read_cur.execute("SELECT %s FROM targets" % _COLS)
            with conn.cursor() as write_cur:
                for rows in _lots(read_cur):
                    updates = []
                    for (tid, url, host, http_status, tech, tags, body_hash, body_len,
                         fh_status, fh_location, body_text, response_headers,
                         sem_verdict) in rows:
                        host_ca = catchall.get(host, {})
                        is_ca = (body_hash in host_ca if body_hash
                                 and not _est_redirection(fh_status) else False)
                        target = _target_dict(
                            url, host, http_status, tech, tags, body_hash, body_len,
                            fh_status, fh_location, is_ca, host_ca.get(body_hash),
                            body_text, response_headers,
                        )
                        score, raisons = signaux.evaluer(target)
                        # S0 : repêchage après le déterministe ; jamais une démotion.
                        if sem_verdict:
                            score, rk = semantique.composer_priorite(score, sem_verdict)
                            if rk:
                                raisons = list(raisons) + [rk]
                        plan = routage.plan(sem_verdict, raisons) if sem_verdict else []
                        new_tags = {
                            **(tags or {}),
                            "methode": "GET",
                            "scannable": gate.is_scannable(target),
                        }
                        updates.append((
                            score, raisons, Json(new_tags),
                            Json(plan) if plan else None, tid,
                        ))
                    write_cur.executemany(_UPDATE_TARGET, updates)
                    scored += len(updates)

        # Un seul commit APRÈS le dernier lot : le dashboard ne voit jamais un scoring
        # partiel et le rebuild séquentiel ne peut commencer avant ce point.
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {"scored": scored}


@app.task(name="score_targets")
def score_targets():
    """Score chaque ligne de targets + gate + démotion consciente de la réponse."""
    return _scorer_targets()


@app.task(name="rebuild_leads")
def rebuild_leads(seuil=1):
    """Régénère la vue curée `leads` (source de vérité) après score_targets : applique
    la MÊME logique que engine/leads.py (1b scope + 1c collapse) et REMPLACE la table.
    targets (détail par endpoint) reste intacte."""
    return _reconstruire_leads(seuil)


def _reconstruire_leads(seuil=1):
    from engine import leads
    lignes, st, remap = leads.construire(seuil)
    n = leads.persister(lignes, remap)
    return {"persistes": n, **st}


@app.task(name="score_targets_puis_rebuild_leads")
def score_targets_puis_rebuild_leads(seuil=1):
    """Pipeline Beat ordonné : commit complet du score, puis seulement le rebuild."""
    score_resume = _scorer_targets()
    rebuild_resume = _reconstruire_leads(seuil)
    return {"score_targets": score_resume, "rebuild_leads": rebuild_resume}
