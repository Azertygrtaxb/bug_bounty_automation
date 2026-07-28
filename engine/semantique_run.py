"""Juge sémantique LLM AVEUGLE sur les corps DÉJÀ stockés — AUCUNE requête réseau vers
les cibles. Le juge ne voit que le CONTENU (extrait + content-type) : jamais l'URL, le
host, le score ni les raisons (cette cécité rend la mesure S4 interprétable).

S1 sélection en base (résidu score 0..SEUIL_RESIDU, vivant, non-asset, non déjà jugé).
S2 extraction aveugle des 8 faits en valeurs FERMÉES (structured outputs).
S3 en lot via l'API Batches (réassocie par custom_id, pas par position).
S5 garde-fous : clé API obligatoire côté worker seulement, plafond de dépense côté code.

Persiste par endpoint : les 8 faits, le verdict (semantique.decider), la date, le modèle,
l'usage tokens. Un endpoint jugé (semantique_juge_le NON NULL) n'est jamais re-jugé.
La clé API n'apparaît dans aucun log, raison, colonne ou CSV.
"""
import os
import time

import psycopg
from psycopg.types.json import Json

from engine.celery_app import app
from knowledge import config, corps, semantique, signaux, sonde

DATABASE_URL = os.environ["DATABASE_URL"]
POLL_SECONDES = int(os.environ.get("SEM_POLL_SECONDES", "15"))

# --- Les 8 faits en valeurs FERMÉES. Les valeurs "porteuses" viennent des tables POIDS de
# semantique.py ; on ajoute leur complément neutre (compté 0). Une valeur hors enum est
# impossible (structured outputs) et ne serait comptée par aucune règle. ---
SCHEMA_FAITS = {
    "type": "object",
    "additionalProperties": False,
    "required": ["portee", "entrees", "objet_parametre", "carte_surface",
                 "structure", "nature_valeurs", "frontiere_auth", "fuite_technique"],
    "properties": {
        "portee":          {"type": "string", "enum": ["par_utilisateur", "public"]},
        "entrees":         {"type": "string", "enum": ["oui", "non"]},
        "objet_parametre": {"type": "string", "enum": ["objet", "aucun"]},
        "carte_surface":   {"type": "string", "enum": ["oui", "non"]},
        "structure":       {"type": "string", "enum": ["narratif", "fonctionnel"]},
        "nature_valeurs":  {"type": "string", "enum": ["descriptif", "operationnel"]},
        "frontiere_auth":  {"type": "string", "enum": ["présente", "absente"]},
        "fuite_technique": {"type": "string", "enum": ["oui", "non"]},
    },
}

SYSTEME_JUGE = (
    "Tu es un analyseur de CONTENU HTTP. On te donne le corps d'une réponse (extrait) et "
    "son content-type — RIEN d'autre : ni URL, ni nom d'hôte, ni score. Détermine 8 faits "
    "sur ce que le contenu EST, en valeurs strictement fermées ; ne devine pas au-delà de "
    "ce qui est montré.\n"
    "- portee: 'par_utilisateur' si le contenu est manifestement des données propres à un "
    "compte/utilisateur identifié ; sinon 'public'.\n"
    "- entrees: 'oui' s'il y a des champs de saisie / formulaire / paramètres d'entrée "
    "applicatifs ; sinon 'non'.\n"
    "- objet_parametre: 'objet' si le contenu manipule un objet métier identifié (fiche, "
    "enregistrement, ressource) ; sinon 'aucun'.\n"
    "- carte_surface: 'oui' si le contenu révèle une carte de surface (liste d'endpoints/"
    "routes/API, doc technique) ; sinon 'non'.\n"
    "- structure: 'narratif' si c'est de la prose/contenu éditorial ; 'fonctionnel' si "
    "c'est une interface/appli/donnée structurée.\n"
    "- nature_valeurs: 'descriptif' si les valeurs décrivent (texte, libellés) ; "
    "'operationnel' si elles pilotent une action/un état.\n"
    "- frontiere_auth: 'présente' si le contenu EST un mur/formulaire d'authentification "
    "ou exige de se connecter ; sinon 'absente'.\n"
    "- fuite_technique: 'oui' si le contenu expose de la technique interne (stacktrace, "
    "config, versions, chemins) ; sinon 'non'.\n"
    "Réponds uniquement via le schéma."
)


def _content_type(response_headers):
    h = response_headers or {}
    for k, v in h.items():
        if isinstance(k, str) and k.lower().replace("-", "_") == "content_type":
            return v
    return "?"


def extrait_aveugle(body_text, response_headers):
    """CONTENU seul : content-type + extrait borné. Jamais l'URL/host/score."""
    corps_txt = (body_text or "")[:config.EXTRAIT_JUGE_MAX]
    return "content-type: %s\n\n%s" % (_content_type(response_headers), corps_txt)


def _est_asset(url):
    t = {"url": url}
    return signaux._is_asset(t) or signaux._is_asset_dir(t)


def selectionner(cur, limite):
    """S1 — le RÉSIDU en base, zéro re-fetch. Trié score DESC (cas limites d'abord)."""
    cur.execute(
        "SELECT id, body_text, response_headers, url, first_hop_location, score "
        "FROM targets WHERE body_text IS NOT NULL AND length(body_text) > 0 "
        "AND score BETWEEN 0 AND %s AND http_status BETWEEN 200 AND 403 "
        "AND semantique_juge_le IS NULL ORDER BY score DESC LIMIT %s",
        (config.SEUIL_RESIDU, limite))
    out = []
    for tid, body, headers, url, fhl, score in cur.fetchall():
        if _est_asset(url):
            continue                      # asset par l'URL (.js/.css/répertoire d'assets)
        if sonde.est_content_type_asset(_content_type(headers)):
            continue                      # asset par le CONTENU (js/css/json servi hors URL .js)
        out.append({"id": tid, "body": body, "headers": headers, "url": url,
                    "fhl": fhl, "score": score})
    return out


def _persister(cur, tid, faits, verdict, modele, usage):
    cur.execute(
        "UPDATE targets SET semantique_faits = %s, semantique_verdict = %s, "
        "semantique_juge_le = now(), semantique_modele = %s, semantique_tokens = %s "
        "WHERE id = %s",
        (Json(faits) if faits is not None else None, verdict, modele,
         Json(usage) if usage is not None else None, tid))


@app.task(name="juger_semantique")
def juger_semantique(limite=None, modele=None):
    """S1→S3. Renvoie un résumé {juges, exclus_auth_wall, erreurs, plafond_atteint, ...}.
    `modele` override (S4.5 : rejouer le même échantillon sur claude-haiku-4-5)."""
    # S5.2 — clé obligatoire, message explicite (pas de trace muette).
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return {"erreur": "ANTHROPIC_API_KEY absente. La variable est-elle déclarée dans le "
                "bloc environment: du service worker (docker-compose.yml) ? Le board ne doit "
                "pas l'avoir."}
    modele = modele or config.MODELE_JUGE
    limite = limite or config.ECHANTILLON_SEM
    plafond = config.MAX_APPELS_JUGE_PAR_RUN

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cands = selectionner(cur, limite)

            # Mur de login MÉCANIQUE (corps.is_auth_wall) : exclu SANS appel API.
            a_juger, exclus = [], 0
            for c in cands:
                wall, _ = corps.is_auth_wall(c["url"], c["body"], c["fhl"])   # renvoie (bool, detail)
                if wall:
                    _persister(cur, c["id"], None, "EXCLU_auth_wall", None, None)
                    exclus += 1
                else:
                    a_juger.append(c)
            conn.commit()

            # S5.4 — plafond de dépense côté code.
            saute_plafond = 0
            if len(a_juger) > plafond:
                saute_plafond = len(a_juger) - plafond
                a_juger = a_juger[:plafond]

            if not a_juger:
                return {"juges": 0, "exclus_auth_wall": exclus, "non_juges_plafond": saute_plafond,
                        "note": "aucun endpoint à juger après exclusions"}

            # S2/S3 — lot Batches (import paresseux : le module se charge sans le SDK).
            from anthropic import Anthropic
            from anthropic.types.messages.batch_create_params import Request
            from anthropic.types.message_create_params import MessageCreateParamsNonStreaming
            client = Anthropic()

            requests = []
            for c in a_juger:
                params = MessageCreateParamsNonStreaming(
                    model=modele,
                    max_tokens=2048,   # couvre raisonnement adaptatif + JSON ; 512 tronquerait
                    system=[{"type": "text", "text": SYSTEME_JUGE,
                             "cache_control": {"type": "ephemeral"}}],
                    output_config={"effort": config.EFFORT_JUGE,
                                   "format": {"type": "json_schema", "schema": SCHEMA_FAITS}},
                    messages=[{"role": "user", "content": extrait_aveugle(c["body"], c["headers"])}],
                )
                requests.append(Request(custom_id=str(c["id"]), params=params))

            batch = client.messages.batches.create(requests=requests)
            while client.messages.batches.retrieve(batch.id).processing_status != "ended":
                time.sleep(POLL_SECONDES)

            juges, erreurs = 0, 0
            for result in client.messages.batches.results(batch.id):
                tid = int(result.custom_id)
                if result.result.type != "succeeded":     # errored/expired : reste non jugé
                    erreurs += 1
                    continue
                msg = result.result.message
                faits = _faits_de_message(msg)
                if faits is None:
                    erreurs += 1
                    continue
                verdict, _ = semantique.decider(faits)
                u = msg.usage
                usage = {"input": getattr(u, "input_tokens", None),
                         "output": getattr(u, "output_tokens", None),
                         "cache_read": getattr(u, "cache_read_input_tokens", None)}
                _persister(cur, tid, faits, verdict, modele, usage)
                juges += 1
            conn.commit()

    return {"juges": juges, "exclus_auth_wall": exclus, "erreurs": erreurs,
            "non_juges_plafond": saute_plafond, "modele": modele}


def _faits_de_message(msg):
    """Extrait le JSON des 8 faits d'un message (structured outputs). Tolérant à la forme
    du SDK : bloc parsé, sinon texte JSON."""
    import json
    for bloc in getattr(msg, "content", []) or []:
        parsed = getattr(bloc, "parsed", None)
        if isinstance(parsed, dict):
            return parsed
        txt = getattr(bloc, "text", None)
        if txt:
            try:
                return json.loads(txt)
            except (ValueError, TypeError):
                continue
    return None
