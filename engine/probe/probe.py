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
from urllib.parse import parse_qsl, urlsplit

import psycopg

from engine import ratelimit
from engine.celery_app import app
from engine.gate import gate
from knowledge import sonde, substance

log = logging.getLogger(__name__)
DATABASE_URL = os.environ["DATABASE_URL"]


def _content_type_stocke(headers):
    """Content-type depuis les response_headers stockés (dict), insensible à la
    casse ET au séparateur ('content-type' / 'Content-Type' / 'content_type')."""
    if not isinstance(headers, dict):
        return None
    for k, v in headers.items():
        if k.lower().replace("-", "_") == "content_type":
            return v
    return None


# Clés de paramètre désignant un identifiant d'objet (aligné sur signaux._ID_PARAM_KEYS).
_ID_QUERY_KEYS = {
    "id", "uid", "uuid", "guid", "account", "accountid", "customer", "customerid",
    "contract", "contractid", "user", "userid", "member", "memberid", "order",
    "orderid", "invoice", "invoiceid", "doc", "docid", "file", "fileid",
    "num", "no", "cat", "pid",
}


def _pattern_and_id(parts):
    """(pattern, id) : remplace l'id VARIABLE par {id}. Gère (1) le dernier segment
    numérique du chemin (/banque/103), et à défaut (2) un paramètre-id de requête
    (/api/...?id=<opaque>) — pour sonder les ids DÉJÀ DÉCOUVERTS d'une API objet-par-id
    (l'espace opaque n'est pas énumérable : on ne sonde que le connu)."""
    segs = parts.path.split("/")
    for i in range(len(segs) - 1, -1, -1):
        if segs[i].isdigit():
            idv = segs[i]
            segs[i] = "{id}"
            pat = "/".join(segs)
            return (pat + "?" + parts.query) if parts.query else pat, idv
    # pas d'id numérique de chemin -> tente un paramètre-id de requête
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    for i, (k, v) in enumerate(pairs):
        kl = k.lower()
        if v and (kl in _ID_QUERY_KEYS or kl.endswith("_id") or kl == "id"):
            q = "&".join((f"{kk}={{id}}" if j == i else f"{kk}={vv}")
                         for j, (kk, vv) in enumerate(pairs))
            return parts.path + "?" + q, v
    return None, None


class _SansRedirection(urllib.request.HTTPRedirectHandler):
    """Ne suit AUCUNE redirection : évite qu'un 3xx nous fasse quitter la cible
    de lancement. On observe le 3xx tel quel (statut + Location), sans le suivre."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _build_opener():
    handlers = [_SansRedirection()]
    if ratelimit.RECON_PROXY:  # point d'accroche egress : IPs tournantes du partenaire
        handlers.append(urllib.request.ProxyHandler(
            {"http": ratelimit.RECON_PROXY, "https": ratelimit.RECON_PROXY}))
    return urllib.request.build_opener(*handlers)


_OPENER = _build_opener()


def _get(url, host_lancement):
    """GET borné, GET UNIQUEMENT. Renvoie (status, corps_texte, content_type).
    Jamais d'écriture.

    Passe d'abord le CONFINEMENT : si le host cible n'est pas le host de lancement
    (ou un sous-domaine), la requête ne part pas (refus dur loggé par le gate).
    Ne suit pas les redirections (pas de sortie de cible par rebond)."""
    try:
        gate.confiner(host_lancement, url)
    except gate.HorsCibleError:
        return None, "", None  # refus dur : requête bloquée (déjà loggée par le gate)
    cible = urlsplit(url).hostname or host_lancement
    ratelimit.throttle_egress(cible)   # CONTRÔLE CENTRAL : cap global + par-filiale
    req = urllib.request.Request(
        url, method="GET",
        headers={"User-Agent": "bb-recon-probe/1.0 (read-only, GET)"},
    )

    def _instrumenter(status, body, t0):
        ratelimit.record_request(cible)
        ratelimit.record_latency((time.time() - t0) * 1000.0)   # latence p50/p95
        sig = ratelimit.est_signal_debit(status, body)          # 429 / challenge = DÉBIT
        if sig:
            ratelimit.signal_debit_et_evaluer(sig)              # accumule + rote si seuil franchi
        if ratelimit.est_reponse_waf(status, url):
            ratelimit.record_waf(cible, status, url)

    t0 = time.time()
    try:
        with _OPENER.open(req, timeout=sonde.TIMEOUT_REQUETE) as resp:
            body = resp.read(sonde.MAX_CORPS_OCTETS)
            ct = resp.headers.get_content_type() if resp.headers else None
            txt = body.decode("utf-8", "replace")
            _instrumenter(resp.status, txt, t0)
            return resp.status, txt, ct
    except urllib.error.HTTPError as e:  # 3xx (non suivi) / 4xx / 5xx
        try:
            body = e.read(sonde.MAX_CORPS_OCTETS).decode("utf-8", "replace")
        except Exception:
            body = ""
        ct = e.headers.get_content_type() if e.headers else None
        _instrumenter(e.code, body, t0)
        return e.code, body, ct
    except Exception as e:  # DNS, TLS, timeout... -> pas de réponse exploitable
        log.warning("sonde: echec GET %s : %s", url, e)
        return None, "", None


def _requete_mutee_full(url, host_lancement, methode="GET", entetes=None):
    """Requête de sonde COMMUNE aux sondes actives (auth-bypass, cors, open-redirect).
    SANS EFFET DE BORD : méthode bornée à GET/HEAD (jamais POST/PUT/DELETE). Même confinement
    dur + throttle + instrumentation que _get. Renvoie (status, corps_texte, headers_dict) —
    headers_dict permet aux sondes de lire ACAO / Location. Les redirections ne sont pas
    suivies (_SansRedirection) : un 3xx est observé tel quel (pas de sortie de cible)."""
    if methode not in sonde.METHODES_AUTORISEES:
        return None, "", {}              # garde-fou dur : aucune méthode à effet de bord
    try:
        gate.confiner(host_lancement, url)
    except gate.HorsCibleError:
        return None, "", {}              # refus dur : requête bloquée (loggée par le gate)
    cible = urlsplit(url).hostname or host_lancement
    ratelimit.throttle_egress(cible)
    h = {"User-Agent": "bb-recon-probe/1.0 (read-only)"}
    h.update(entetes or {})
    req = urllib.request.Request(url, method=methode, headers=h)
    t0 = time.time()

    def _instr(status, body):
        ratelimit.record_request(cible)
        ratelimit.record_latency((time.time() - t0) * 1000.0)
        sig = ratelimit.est_signal_debit(status, body)
        if sig:
            ratelimit.signal_debit_et_evaluer(sig)
        if ratelimit.est_reponse_waf(status, url):
            ratelimit.record_waf(cible, status, url)

    def _entetes(resp_headers):
        return {k.lower(): v for k, v in resp_headers.items()} if resp_headers else {}

    try:
        with _OPENER.open(req, timeout=sonde.TIMEOUT_REQUETE) as resp:
            body = resp.read(sonde.MAX_CORPS_OCTETS).decode("utf-8", "replace")
            _instr(resp.status, body)
            return resp.status, body, _entetes(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(sonde.MAX_CORPS_OCTETS).decode("utf-8", "replace")
        except Exception:
            body = ""
        _instr(e.code, body)
        return e.code, body, _entetes(e.headers)
    except Exception as e:
        log.warning("sonde: echec %s %s : %s", methode, url, e)
        return None, "", {}


def _requete_mutee(url, host_lancement, methode="GET", entetes=None):
    """Compat auth-bypass : (status, corps, content_type). Enveloppe _requete_mutee_full."""
    st, body, headers = _requete_mutee_full(url, host_lancement, methode, entetes)
    ct = (headers.get("content-type") or "").split(";")[0] or None
    return st, body, ct


def _mutations_bypass(url):
    """Matrice de contournement 401/403, EN LECTURE SEULE. Chaque entrée = (label, méthode,
    entêtes, url_mutée). Bornée par sonde.AUTH_MAX_MUTATIONS_PAR_ENDPOINT. Générique (aucune
    valeur host-spécifique). Ne modifie jamais le corps ni n'émet de méthode à effet de bord."""
    parts = urlsplit(url)
    base = "%s://%s" % (parts.scheme, parts.netloc)
    path = parts.path or "/"
    q = ("?" + parts.query) if parts.query else ""
    muts = [
        # En-têtes de confiance / réécriture d'URL couramment mal validés en périphérie.
        ("xff-127",         "GET",  {"X-Forwarded-For": "127.0.0.1"},          url),
        ("x-original-url",  "GET",  {"X-Original-URL": path},                   base + "/" + q),
        ("x-rewrite-url",   "GET",  {"X-Rewrite-URL": path},                    base + "/" + q),
        ("x-forwarded-host","GET",  {"X-Forwarded-Host": "localhost"},         url),
        # Mutations de chemin : traversée de séparateur souvent traitée après l'ACL.
        ("path-semicolon",  "GET",  {},  base + path + "..;/" + q),
        ("path-trailing",   "GET",  {},  base + path + "/" + q if not path.endswith("/") else url),
        ("path-dotslash",   "GET",  {},  base + path + "/." + q),
        # Méthode alternative sans effet de bord (certaines ACL ne couvrent que GET).
        ("head",            "HEAD", {},  url),
    ]
    return muts[:sonde.AUTH_MAX_MUTATIONS_PAR_ENDPOINT]


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
    """Verdict DÉTERMINISTE, PER-ID (jamais de vote majoritaire) : l'outlier data fait
    la cible, pas la majorité. Chaque id sondé est jugé par son content-type."""
    vivants = [(idv, body, ct) for idv, st, body, ct in reponses if st == 200 and body]
    n200 = len(vivants)
    base = {"pattern": pattern, "n_sonde": len(reponses), "n200": n200,
            "borne_status": borne_status}
    borne_txt = f", borne id={sonde.ID_BORNE}->{borne_status}" if borne_status is not None else ""
    if n200 < 1:
        return {**base, "verdict": "indetermine", "delta": 0,
                "texte": f"sonde: 0 reponse 200 exploitable sur {len(reponses)} id -> indetermine"}

    # PER-ID : sépare les id-asset (public par nature) des id-DATA (donnée possédée
    # potentielle : html/json/xml/pdf/octet-stream/plain).
    data = [(idv, body) for idv, body, ct in vivants if not sonde.est_content_type_asset(ct)]
    assets = [(idv, ct) for idv, _, ct in vivants if sonde.est_content_type_asset(ct)]

    # TOUS les échantillons sont des assets -> public_asset (+ malus, borné, jamais retiré).
    if not data:
        cts = ",".join(sorted(set((ct or "").split(";")[0] for _, ct in assets)))
        return {**base, "verdict": "public_asset", "delta": sonde.MALUS_ASSET_PUBLIC,
                "texte": f"sonde: {len(assets)}/{n200} id assets ({cts}), aucun non-asset -> public_asset{borne_txt}"}

    # AU MOINS un id non-asset -> ESCALADE (aucun malus). L'outlier data fait la cible.
    outliers = ",".join(idv for idv, _ in data)
    if len(data) < 2:
        # Un seul id data parmi des assets : on ne peut pas comparer, mais on NE noie
        # PAS l'outlier -> escalade vers le juge sémantique (étape 2).
        return {**base, "verdict": "candidat_data", "delta": 0,
                "texte": f"sonde: {len(assets)} asset + 1 non-asset (id={outliers}) -> escalade candidat_data (outlier donnee, juge etape 2){borne_txt}"}

    # Plusieurs id data : similarité SUR LES DONNÉES seulement (assets écartés).
    sim = round(_similarite([b for _, b in data]), 3)
    base["similarite"] = sim
    n_asset_txt = f" ({len(assets)} asset ecarte(s))" if assets else ""
    if sim >= sonde.SIMILARITE_IDENTIQUE:
        return {**base, "verdict": "probable_public", "delta": sonde.MALUS_PROBABLE_PUBLIC,
                "texte": f"sonde: contenu identique sur {len(data)} id non-asset (sim={sim}{borne_txt}){n_asset_txt} -> probable public"}
    if sim >= sonde.SIMILARITE_GABARIT_MIN and len(data) >= sonde.MIN_200_STABLE:
        return {**base, "verdict": "candidat_serieux", "delta": sonde.BONUS_CANDIDAT_SERIEUX,
                "texte": f"sonde: {len(data)} id non-asset en 200, contenu diff structure (sim={sim}{borne_txt}){n_asset_txt} -> candidat serieux"}
    return {**base, "verdict": "indetermine", "delta": 0,
            "texte": f"sonde: {len(data)} id non-asset, similarite {sim} hors seuils{borne_txt}{n_asset_txt} -> indetermine"}


def _sonder_groupe(scheme, netloc, pattern, membres, budget, host_lancement):
    """Sonde un groupe /pattern/{id} : GET throttlés, confinés, dans la limite du budget."""
    # Tri stable : ids numériques d'abord (ordre naturel), puis opaques (lexical).
    def _cle(m):
        idv = m["idv"]
        return (0, int(idv), "") if idv.isdigit() else (1, 0, idv)
    echantillon = sorted(membres, key=_cle)[:sonde.TAILLE_ECHANTILLON]
    reponses = []
    for m in echantillon:
        if budget["restant"] <= 0:
            break
        st, body, ct = _get(m["url"], host_lancement)
        budget["restant"] -= 1
        log.info("sonde GET status=%s ct=%s len=%s budget=%s url=%s",
                 st, ct, len(body), budget["restant"], m["url"])
        reponses.append((m["idv"], st, body, ct))
        time.sleep(sonde.DELAI_ENTRE_REQUETES)

    borne_status = None
    if sonde.SONDER_BORNE and budget["restant"] > 0:
        borne_url = f"{scheme}://{netloc}" + pattern.replace("{id}", str(sonde.ID_BORNE))
        borne_status, _, _ = _get(borne_url, host_lancement)
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
                SELECT id, url, http_status, score, response_headers
                FROM targets
                WHERE array_to_string(score_raisons, ',') LIKE %s
                  AND (http_status = 200 OR http_status BETWEEN 300 AND 399)
                  AND (host = %s OR host LIKE %s)
                """,
                ("%id_non_derive_session%", host, "%." + host),
            )
            rows = cur.fetchall()

    # COURT-CIRCUIT content-type STOCKÉ, CONDITIONNEL À LA VALEUR (FIX 2) :
    #  - score < SEUIL_SONDE (faible valeur) ET type stocké = asset -> on fait confiance
    #    à l'échantillon stocké : public_asset + malus, 0 requête (efficacité sûre) ;
    #  - score >= SEUIL_SONDE (lead à valeur) -> on NE court-circuite PAS : on sonde
    #    d'AUTRES ids découverts et on juge per-id (on ne parie pas sur un seul échantillon).
    a_sonder = []
    court_circuits = []
    for row_id, url, status, score, headers in rows:
        ct = _content_type_stocke(headers)
        if (score or 0) < sonde.SEUIL_SONDE and ct and sonde.est_content_type_asset(ct):
            court_circuits.append({"row_id": row_id, "url": url, "ct": ct})
        else:
            a_sonder.append((row_id, url, status, score))

    for cc in court_circuits:
        texte = ("sonde: content-type stocke %s, score<%d -> public_asset (court-circuit, 0 requete)"
                 % ((cc["ct"] or "").split(";")[0], sonde.SEUIL_SONDE))
        _appliquer({"delta": sonde.MALUS_ASSET_PUBLIC, "texte": texte}, [{"row_id": cc["row_id"]}])

    # Groupe par (schéma, netloc, pattern-à-id-variable) — sur les NON court-circuités.
    groupes = {}
    for row_id, url, status, score in a_sonder:
        parts = urlsplit(url)
        pattern, idv = _pattern_and_id(parts)
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
        "public_asset_court_circuit": len(court_circuits),
        "requetes_utilisees": sonde.MAX_REQUETES_PAR_HOST - budget["restant"],
        "requetes_economisees_court_circuit": len(court_circuits),
        "budget_max": sonde.MAX_REQUETES_PAR_HOST,
        "hors_cible_marques": hors_cible,
        "verdicts": verdicts,
    }


def _plan_contient(sonde_plan, famille):
    """True si le sonde_plan JSONB (list[dict]) contient la famille demandée."""
    if not isinstance(sonde_plan, list):
        return False
    return any(isinstance(e, dict) and e.get("famille") == famille for e in sonde_plan)


@app.task(name="probe_auth_bypass")
def probe_auth_bypass(host):
    """Sonde AUTH-BYPASS (brique B), CONFINÉE au host de lancement.

    Ne sonde QUE les endpoints dont sonde_plan contient 'auth_bypass' (routage à convergence
    stricte : verdict sémantique surface_auth + signal déterministe d'auth), vivants en
    401/403, situés sur le host de lancement (ou un sous-domaine). Pour chacun : baseline
    (le refus), puis matrice de mutations EN LECTURE SEULE. N'affirme un contournement que
    sur un 401/403 -> 200 dont le CONTENU s'écarte réellement du refus (preuve EXÉCUTÉE ;
    un 200 identique au refus est un faux positif écarté). Ne conclut jamais 'vulnérable' :
    ajuste le score + écrit une observation traçable. La preuve finale reste humaine."""
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, url, http_status, sonde_plan
                FROM targets
                WHERE sonde_plan IS NOT NULL
                  AND http_status = ANY(%s)
                  AND (host = %s OR host LIKE %s)
                ORDER BY score DESC
                """,
                (list(sonde.AUTH_STATUTS_CIBLES), host, "%." + host),
            )
            rows = cur.fetchall()

    a_sonder = [(rid, url, st) for rid, url, st, plan in rows
                if _plan_contient(plan, "auth_bypass")][:sonde.AUTH_MAX_ENDPOINTS_PAR_HOST]

    budget = {"restant": sonde.MAX_REQUETES_PAR_HOST}
    resultats = []
    for rid, url, statut_baseline in a_sonder:
        if budget["restant"] <= 1:
            log.warning("sonde auth-bypass: budget epuise, arret (ROE)")
            break
        # Baseline : le refus tel qu'il est (confirme le statut + capture le corps de refus).
        st0, refus, _ = _requete_mutee(url, host, "GET")
        budget["restant"] -= 1
        time.sleep(sonde.DELAI_ENTRE_REQUETES)
        if st0 not in sonde.AUTH_STATUTS_CIBLES:
            continue  # plus en 401/403 (changé depuis le scan) -> rien à contourner

        bypass = None
        for label, methode, entetes, url_mut in _mutations_bypass(url):
            if budget["restant"] <= 0:
                break
            st, body, _ = _requete_mutee(url_mut, host, methode, entetes)
            budget["restant"] -= 1
            time.sleep(sonde.DELAI_ENTRE_REQUETES)
            # PREUVE EXÉCUTÉE : 200 obtenu ET contenu réellement différent du refus baseline.
            if st == 200 and body:
                sim = round(_similarite([refus, body]), 3)
                if sim < sonde.AUTH_SIMILARITE_MAX_AVEC_REFUS:
                    bypass = {"label": label, "methode": methode, "sim_refus": sim}
                    break  # un contournement crédible suffit : on n'insiste pas (ROE)

        if bypass:
            texte = ("sonde auth-bypass: %d->200 via '%s' (%s), contenu != refus (sim=%s) "
                     "-> CONTOURNEMENT CREDIBLE (preuve executee, verif humaine requise)"
                     % (statut_baseline, bypass["label"], bypass["methode"], bypass["sim_refus"]))
            _appliquer({"delta": sonde.BONUS_AUTH_BYPASS, "texte": texte}, [{"row_id": rid}])
            resultats.append({"row_id": rid, "url": url, **bypass})
        else:
            _appliquer({"delta": 0,
                        "texte": "sonde auth-bypass: %d, aucune mutation ne contourne (%d essais) "
                                 "-> pas de bypass" % (statut_baseline,
                                                       len(_mutations_bypass(url)))},
                       [{"row_id": rid}])

    return {
        "host": host,
        "endpoints_planifies": len(a_sonder),
        "bypass_credibles": len(resultats),
        "requetes_utilisees": sonde.MAX_REQUETES_PAR_HOST - budget["restant"],
        "budget_max": sonde.MAX_REQUETES_PAR_HOST,
        "resultats": resultats,
    }


def _endpoints_planifies(host, famille, statuts=None, limite=None):
    """Sélection COMMUNE aux sondes de plan : endpoints dont sonde_plan contient `famille`,
    sur le host de lancement (ou sous-domaine), triés par score. `statuts` filtre le http_status
    si fourni. Confinement host garanti par la clause SQL + gate.confiner à l'émission."""
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            if statuts:
                cur.execute(
                    "SELECT id, url, http_status, sonde_plan FROM targets "
                    "WHERE sonde_plan IS NOT NULL AND http_status = ANY(%s) "
                    "AND (host = %s OR host LIKE %s) ORDER BY score DESC",
                    (list(statuts), host, "%." + host))
            else:
                cur.execute(
                    "SELECT id, url, http_status, sonde_plan FROM targets "
                    "WHERE sonde_plan IS NOT NULL "
                    "AND (host = %s OR host LIKE %s) ORDER BY score DESC",
                    (host, "%." + host))
            rows = cur.fetchall()
    sel = [(rid, url, st) for rid, url, st, plan in rows if _plan_contient(plan, famille)]
    return sel[:limite] if limite else sel


@app.task(name="probe_cors")
def probe_cors(host):
    """Sonde CORS (brique B), CONFINÉE au host de lancement.

    Ne sonde que les endpoints planifiés 'cors' (applicatif + cors_permissif), sur le host de
    lancement. Rejoue chaque endpoint avec une Origin ATTAQUANTE et lit la réponse : preuve
    EXÉCUTÉE d'un CORS exploitable = ACAO REFLÈTE notre origine (== origine envoyée, ou '*')
    ET Allow-Credentials:true — un navigateur tiers lirait alors la réponse authentifiée. Un
    ACAO fixe (allowlist) n'est PAS un reflet -> non exploitable. Ne conclut jamais
    'vulnérable' : ajuste le score + observation traçable. Preuve finale humaine."""
    a_sonder = _endpoints_planifies(host, "cors",
                                    limite=sonde.CORS_MAX_ENDPOINTS_PAR_HOST)
    budget = {"restant": sonde.MAX_REQUETES_PAR_HOST}
    resultats = []
    for rid, url, _ in a_sonder:
        if budget["restant"] <= 0:
            log.warning("sonde cors: budget epuise, arret (ROE)")
            break
        st, _body, headers = _requete_mutee_full(
            url, host, "GET", {"Origin": sonde.CORS_ORIGIN_ATTAQUANT})
        budget["restant"] -= 1
        time.sleep(sonde.DELAI_ENTRE_REQUETES)
        if st is None:
            continue
        acao = (headers.get("access-control-allow-origin") or "").strip()
        creds = (headers.get("access-control-allow-credentials") or "").strip().lower() == "true"
        reflete = (acao == sonde.CORS_ORIGIN_ATTAQUANT) or (acao == "*")
        if reflete and creds:
            texte = ("sonde cors: Origin attaquante REFLETEE (ACAO=%s, creds=true) "
                     "-> lecture cross-origin authentifiee CREDIBLE (preuve executee, "
                     "verif humaine requise)" % (acao or "*"))
            _appliquer({"delta": sonde.BONUS_CORS_REFLETE, "texte": texte}, [{"row_id": rid}])
            resultats.append({"row_id": rid, "url": url, "acao": acao, "creds": creds})
        else:
            _appliquer({"delta": 0,
                        "texte": "sonde cors: ACAO=%r creds=%s -> pas de reflet exploitable"
                                 % (acao or None, creds)}, [{"row_id": rid}])

    return {"host": host, "endpoints_planifies": len(a_sonder),
            "reflets_credibles": len(resultats),
            "requetes_utilisees": sonde.MAX_REQUETES_PAR_HOST - budget["restant"],
            "resultats": resultats}


def _payloads_open_redirect(domaine):
    """Variantes d'injection open-redirect (LECTURE SEULE), bornées. Générique, sans valeur
    host-spécifique. On teste des formes couramment mal filtrées pointant un domaine EXTERNE."""
    return [
        "https://%s" % domaine,
        "//%s" % domaine,
        "https:/%s" % domaine,
        "https://%s/%%2f.." % domaine,
    ][:sonde.OPENREDIR_MAX_PAYLOADS]


def _muter_param_redirect(url, payload):
    """Remplace la valeur des paramètres de redirection connus par `payload`. Renvoie l'URL
    mutée, ou None si l'URL n'a aucun paramètre de redirection (rien à tester)."""
    from urllib.parse import urlencode, parse_qsl, urlunsplit
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    touche = False
    nouveaux = []
    for k, v in pairs:
        if k.lower() in substance.REDIRECT_PARAMS:
            nouveaux.append((k, payload))
            touche = True
        else:
            nouveaux.append((k, v))
    if not touche:
        return None
    return urlunsplit((parts.scheme, parts.netloc, parts.path,
                       urlencode(nouveaux), parts.fragment))


@app.task(name="probe_open_redirect")
def probe_open_redirect(host):
    """Sonde OPEN-REDIRECT (brique B), CONFINÉE au host de lancement.

    Ne sonde que les endpoints planifiés 'open_redirect' (applicatif + open_redirect_possible),
    sur le host de lancement. Mute le paramètre de redirection vers un domaine EXTERNE témoin
    et lit la Location du premier-hop (redirection NON suivie). Preuve EXÉCUTÉE = la Location
    pointe réellement le domaine externe injecté (pas seulement le reflète dans une page).
    Ne conclut jamais 'vulnérable' : ajuste le score + observation. Preuve finale humaine."""
    a_sonder = _endpoints_planifies(host, "open_redirect",
                                    limite=sonde.OPENREDIR_MAX_ENDPOINTS_PAR_HOST)
    budget = {"restant": sonde.MAX_REQUETES_PAR_HOST}
    resultats = []
    for rid, url, _ in a_sonder:
        confirme = None
        for payload in _payloads_open_redirect(sonde.OPENREDIR_DOMAINE_TEMOIN):
            if budget["restant"] <= 0:
                break
            url_mut = _muter_param_redirect(url, payload)
            if url_mut is None:
                break  # aucun param de redirection dans cette URL -> rien à tester
            st, _body, headers = _requete_mutee_full(url_mut, host, "GET")
            budget["restant"] -= 1
            time.sleep(sonde.DELAI_ENTRE_REQUETES)
            loc = (headers.get("location") or "")
            # Preuve : redirection (3xx) dont la destination est le domaine externe témoin.
            if st is not None and 300 <= st < 400 and loc:
                dest_host = (urlsplit(loc).hostname or "").lower()
                if dest_host == sonde.OPENREDIR_DOMAINE_TEMOIN:
                    confirme = {"payload": payload, "status": st, "location": loc[:200]}
                    break
        if confirme:
            texte = ("sonde open-redirect: param redirige vers domaine EXTERNE temoin "
                     "(%d -> %s) via %r -> OPEN REDIRECT PROUVE (preuve executee, verif "
                     "humaine requise)" % (confirme["status"], confirme["location"],
                                           confirme["payload"]))
            _appliquer({"delta": sonde.BONUS_OPEN_REDIRECT, "texte": texte}, [{"row_id": rid}])
            resultats.append({"row_id": rid, "url": url, **confirme})
        elif budget["restant"] <= 0:
            break

    return {"host": host, "endpoints_planifies": len(a_sonder),
            "open_redirects_prouves": len(resultats),
            "requetes_utilisees": sonde.MAX_REQUETES_PAR_HOST - budget["restant"],
            "resultats": resultats}
