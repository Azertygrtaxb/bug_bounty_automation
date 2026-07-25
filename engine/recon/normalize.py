"""Normalisation d'URL, hash de déduplication, et calcul des tags statiques.

Aucune requête réseau ici : purement déterministe (même URL -> même sortie),
donc c'est du script, jamais de l'IA.
"""
import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from knowledge.dedup import PLACEHOLDERS, VOLATILE_PARAMS
from knowledge.substance import ERROR_RETURN_PARAMS

# Params retirés du hash de dédup : volatils + params de retour réfléchis.
_STRIP_DEDUP = VOLATILE_PARAMS | ERROR_RETURN_PARAMS

DEFAULT_PORTS = {"http": "80", "https": "443"}


def normalize_url(raw):
    """Canonise une URL pour que deux formes équivalentes aient le même hash.

    - schéma/host en minuscules
    - port par défaut retiré
    - slash final retiré (sauf racine)
    - paramètres de requête triés, fragment supprimé
    - paramètres VOLATILES (session/tracking/transient) retirés, pour que les
      variantes d'un même endpoint fusionnent (liste dans knowledge/dedup.py)
    Retourne None si l'entrée n'a pas de host exploitable.
    """
    if not raw:
        return None
    parts = urlsplit(raw.strip())
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    if not host:
        return None
    netloc = host
    if parts.port and str(parts.port) != DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{parts.port}"
    path = parts.path or "/"
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    stable = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
              if k.lower() not in VOLATILE_PARAMS]
    query = urlencode(sorted(stable))
    return urlunsplit((scheme, netloc, path, query, ""))


def url_hash(normalized):
    """SHA-256 de l'URL normalisée : sert de hash_dedup."""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def dedup_key(url):
    """Clé canonique pour la déduplication, plus agressive que normalize_url.

    Décode ENTIÈREMENT la query (plusieurs passes) pour exposer les tokens
    volatils IMBRIQUÉS dans une valeur de paramètre (ex. `wct` niché dans
    `sourceURL`), neutralise l'artefact `&amp;`, retire tous les paramètres
    volatils (knowledge/dedup.py) à n'importe quel niveau, puis trie. Deux URLs
    du même endpoint ne différant que par des tokens volatils -> même clé."""
    if not url:
        return ""
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "http").lower()
    host = (parts.hostname or "").lower()
    path = parts.path or "/"
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    # Parse à UN SEUL niveau : on retire les params de retour (sourceURL...) EN
    # ENTIER sans décoder leur valeur — sinon un décodage récursif exposerait les
    # tokens nichés dedans (wctx -> id/rm/ru...) qui re-différencieraient les
    # variantes. Les tokens volatils nichés dans un param de retour disparaissent
    # avec lui.
    q = parts.query.replace("&amp;", "&")
    kept = []
    for key, val in parse_qsl(q, keep_blank_values=True):
        k = key.lower().strip()
        v = (val or "").strip()
        if not k or k in _STRIP_DEDUP:
            continue                       # volatil ou param de retour réfléchi
        if not v or v.lower() in PLACEHOLDERS:
            continue                       # valeur vide (?amp=) ou placeholder (EXPR)
        kept.append((k, val))
    kept.sort()
    return urlunsplit((scheme, host, path, urlencode(kept), ""))


# --- Tags statiques (signaux bruts, pas de scoring) ---------------------------

_SWAGGER_RE = re.compile(r"(swagger|openapi|api-docs|redoc)", re.IGNORECASE)
_GRAPHQL_RE = re.compile(r"/(graphql|graphiql|gql)(/|$|\?)", re.IGNORECASE)
_NUMERIC_SEG_RE = re.compile(r"/\d+(?:/|$)")
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)
_ID_PARAM_KEYS = {
    "id", "uid", "uuid", "guid", "account", "customer", "contract",
    "user", "member", "order", "invoice", "doc", "file", "num", "no", "cat", "pid",
}


def _id_in_url(normalized):
    """Heuristique : un identifiant potentiellement manipulable (IDOR) dans l'URL."""
    parts = urlsplit(normalized)
    if _NUMERIC_SEG_RE.search(parts.path):
        return True
    if _UUID_RE.search(parts.path) or _UUID_RE.search(parts.query):
        return True
    for key, _ in parse_qsl(parts.query, keep_blank_values=True):
        kl = key.lower()
        if kl in _ID_PARAM_KEYS or kl.endswith("_id") or kl == "id":
            return True
    return False


def compute_tags(normalized, extra=None):
    """tags JSONB : au minimum has_swagger / has_graphql / id_in_url, + méta optionnelle."""
    tags = {
        "has_swagger": bool(_SWAGGER_RE.search(normalized)),
        "has_graphql": bool(_GRAPHQL_RE.search(normalized)),
        "id_in_url": _id_in_url(normalized),
    }
    if extra:
        tags.update({k: v for k, v in extra.items() if v not in (None, "", [], {})})
    return tags
