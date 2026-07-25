"""Sonde comportementale (étape SÉPARÉE, après le scoring).

Ne tourne QUE sur les candidats /pattern/{id} déjà en base, déjà flaggés
id_non_derive_session, déjà vivants (200/3xx). Compare les réponses de plusieurs
id d'un même pattern et repriorise le groupe.

Garde-fous ROE, appliqués MÉCANIQUEMENT (jamais laissés au jugement) :
  - GET uniquement (aucun effet de bord) ;
  - débit throttlé + budget dur de requêtes / host (knowledge/sonde.py) ;
  - échantillon borné d'id déjà découverts (+ 1 id de borne) ;
  - ne conclut jamais « IDOR confirmé » : ajuste un score, écrit une observation.
"""
import logging
import os
import time
import urllib.error
import urllib.request
from difflib import SequenceMatcher
from urllib.parse import urlsplit

import psycopg

from engine.celery_app import app
from engine.gate import gate
from knowledge import sonde

log = logging.getLogger(__name__)
DATABASE_URL = os.environ["DATABASE_URL"]


def _pattern_and_id(path):
    """Remplace le dernier segment purement numérique par {id}. -> (pattern, id)."""
    segs = path.split("/")
    for i in range(len(segs) - 1, -1, -1):
        if segs[i].isdigit():
            idv = segs[i]
            segs[i] = "{id}"
            return "/".join(segs), idv
    return None, None


class _SansRedirection(urllib.request.HTTPRedirectHandler):
    """Ne suit AUCUNE redirection : évite qu'un 3xx nous fasse quitter la cible
    de lancement. On observe le 3xx tel quel (statut + Location), sans le suivre."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_SansRedirection())


def _get(url, host_lancement):
    """GET borné, GET UNIQUEMENT. Renvoie (status, corps_texte). Jamais d'écriture.

    Passe d'abord le CONFINEMENT : si le host cible n'est pas le host de lancement
    (ou un sous-domaine), la requête ne part pas (refus dur loggé par le gate).
    Ne suit pas les redirections (pas de sortie de cible par rebond)."""
    try:
        gate.confiner(host_lancement, url)
    except gate.HorsCibleError:
        return None, ""  # refus dur : requête bloquée (déjà loggée par le gate)
    req = urllib.request.Request(
        url, method="GET",
        headers={"User-Agent": "bb-recon-probe/1.0 (read-only, GET)"},
    )
    try:
        with _OPENER.open(req, timeout=sonde.TIMEOUT_REQUETE) as resp:
            body = resp.read(sonde.MAX_CORPS_OCTETS)
            return resp.status, body.decode("utf-8", "replace")
    except urllib.error.HTTPError as e:  # 3xx (non suivi) / 4xx / 5xx
        try:
            body = e.read(sonde.MAX_CORPS_OCTETS).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:  # DNS, TLS, timeout... -> pas de réponse exploitable
        log.warning("sonde: echec GET %s : %s", url, e)
        return None, ""


def _similarite(bodies):
    """Similarité moyenne (difflib ratio 0..1) entre paires de corps, fenêtrée."""
    w = sonde.FENETRE_COMPARAISON
    cut = [b[:w] for b in bodies]
    pairs = [(i, j) for i in range(len(cut)) for j in range(i + 1, len(cut))]
    if not pairs:
        return 1.0
    ratios = [SequenceMatcher(None, cut[i], cut[j]).ratio() for i, j in pairs]
    return sum(ratios) / len(ratios)


def _comparer(pattern, reponses, borne_status):
    """Verdict DÉTERMINISTE à partir des réponses observées (aucun jugement de sens)."""
    vivants = [(idv, body) for idv, st, body in reponses if st == 200 and body]
    n200 = len(vivants)
    base = {"pattern": pattern, "n_sonde": len(reponses), "n200": n200,
            "borne_status": borne_status}
    if n200 < 2:
        return {**base, "verdict": "indetermine", "delta": 0,
                "texte": f"sonde: {n200} reponse(s) 200 exploitable(s) sur {len(reponses)} id -> indetermine"}

    sim = round(_similarite([b for _, b in vivants]), 3)
    base["similarite"] = sim
    borne_txt = f", borne id={sonde.ID_BORNE}->{borne_status}" if borne_status is not None else ""

    if sim >= sonde.SIMILARITE_IDENTIQUE:
        return {**base, "verdict": "probable_public", "delta": sonde.MALUS_PROBABLE_PUBLIC,
                "texte": f"sonde: contenu identique sur {n200} id (sim={sim}{borne_txt}) -> probable public"}
    if sim >= sonde.SIMILARITE_GABARIT_MIN and n200 >= sonde.MIN_200_STABLE:
        return {**base, "verdict": "candidat_serieux", "delta": sonde.BONUS_CANDIDAT_SERIEUX,
                "texte": f"sonde: 200 stable sur {n200} id, contenu diff structure (sim={sim}{borne_txt}) -> candidat serieux"}
    return {**base, "verdict": "indetermine", "delta": 0,
            "texte": f"sonde: {n200} id en 200, similarite {sim} hors seuils{borne_txt} -> indetermine"}


def _sonder_groupe(scheme, netloc, pattern, membres, budget, host_lancement):
    """Sonde un groupe /pattern/{id} : GET throttlés, confinés, dans la limite du budget."""
    echantillon = sorted(membres, key=lambda m: int(m["idv"]))[:sonde.TAILLE_ECHANTILLON]
    reponses = []
    for m in echantillon:
        if budget["restant"] <= 0:
            break
        st, body = _get(m["url"], host_lancement)
        budget["restant"] -= 1
        log.info("sonde GET status=%s len=%s budget=%s url=%s",
                 st, len(body), budget["restant"], m["url"])
        reponses.append((m["idv"], st, body))
        time.sleep(sonde.DELAI_ENTRE_REQUETES)

    borne_status = None
    if sonde.SONDER_BORNE and budget["restant"] > 0:
        borne_url = f"{scheme}://{netloc}" + pattern.replace("{id}", str(sonde.ID_BORNE))
        borne_status, _ = _get(borne_url, host_lancement)
        budget["restant"] -= 1
        log.info("sonde GET-borne status=%s budget=%s url=%s",
                 borne_status, budget["restant"], borne_url)
        time.sleep(sonde.DELAI_ENTRE_REQUETES)

    return _comparer(pattern, reponses, borne_status)


def _appliquer(verdict, membres):
    """Repriorise le groupe : ajuste le score, ajoute l'observation traçable."""
    delta, texte = verdict["delta"], verdict["texte"]
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            for m in membres:
                cur.execute(
                    """
                    UPDATE targets
                    SET score = GREATEST(0, score + %s),
                        score_raisons = array_append(score_raisons, %s)
                    WHERE id = %s
                    """,
                    (delta, texte, m["row_id"]),
                )
        conn.commit()


def _marquer_hors_cible(host_lancement):
    """Marque en base (sans les sonder) les candidats id vivants situés HORS de la
    cible de lancement — tiers ou autres filiales vus par rebond en découverte.
    Aucune requête émise : c'est une trace pour un run dédié ultérieur."""
    marque = f"hors_cible_de_lancement:{host_lancement}"
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE targets
                SET score_raisons = array_append(score_raisons, %s)
                WHERE array_to_string(score_raisons, ',') LIKE %s
                  AND http_status = 200
                  AND host <> %s AND host NOT LIKE %s
                  AND array_to_string(score_raisons, ',') NOT LIKE %s
                """,
                (marque, "%id_non_derive_session%", host_lancement,
                 "%." + host_lancement, "%hors_cible_de_lancement%"),
            )
            n = cur.rowcount
        conn.commit()
    return n


@app.task(name="probe_idor_candidates")
def probe_idor_candidates(host):
    """Sonde comportementale bornée, CONFINÉE au host de lancement.

    Ne sonde que les candidats id vivants situés sur le host de lancement (ou un
    sous-domaine). Les candidats hors-cible vus par rebond sont marqués en base,
    jamais sondés."""
    # Sélection confinée : host de lancement OU un de ses sous-domaines.
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, url, http_status, score
                FROM targets
                WHERE array_to_string(score_raisons, ',') LIKE %s
                  AND (http_status = 200 OR http_status BETWEEN 300 AND 399)
                  AND (host = %s OR host LIKE %s)
                """,
                ("%id_non_derive_session%", host, "%." + host),
            )
            rows = cur.fetchall()

    # Groupe par (schéma, netloc, pattern-à-id-variable)
    groupes = {}
    for row_id, url, status, score in rows:
        parts = urlsplit(url)
        pattern, idv = _pattern_and_id(parts.path)
        if pattern is None:
            continue
        groupes.setdefault((parts.scheme, parts.netloc, pattern), []).append(
            {"row_id": row_id, "url": url, "idv": idv, "score": score})

    budget = {"restant": sonde.MAX_REQUETES_PAR_HOST}
    verdicts = []
    for (scheme, netloc, pattern), membres in groupes.items():
        if len({m["idv"] for m in membres}) < 2:
            continue  # besoin d'au moins 2 id pour comparer
        if budget["restant"] <= 0:
            log.warning("sonde: budget de requetes epuise, arret (ROE)")
            break
        verdict = _sonder_groupe(scheme, netloc, pattern, membres, budget, host)
        _appliquer(verdict, membres)
        verdicts.append({"pattern": pattern, "membres": len(membres),
                         "verdict": verdict["verdict"], "delta": verdict["delta"],
                         "similarite": verdict.get("similarite")})

    hors_cible = _marquer_hors_cible(host)

    return {
        "host": host,
        "groupes_id_dans_cible": len(groupes),
        "requetes_utilisees": sonde.MAX_REQUETES_PAR_HOST - budget["restant"],
        "budget_max": sonde.MAX_REQUETES_PAR_HOST,
        "hors_cible_marques": hors_cible,
        "verdicts": verdicts,
    }
