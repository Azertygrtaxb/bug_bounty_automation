"""RÉCOLTE D'IDS — extraction déterministe de tokens id-like par SHAPE GÉNÉRIQUE.

Cœur BORNÉ : débloque le BOLA sur id opaque en fournissant à la sonde des ids
récoltés dans les corps DÉJÀ CAPTURÉS + les params des URLs découvertes, plus une
génération séquentielle bornée pour les ids numériques.

GÉNÉRIQUE, DÉTERMINISTE (aucune IA ici — l'IA n'intervient qu'au juge en aval).
AUCUN format host-spécifique : un « Fkey »/« checkCode » = token opaque reconnu par
sa SHAPE (longueur + classe de caractères), pas par son nom.

CE QU'ON NE FAIT PAS (borne dure) : aucune source externe (google/wayback), aucun
crawl de listings, aucun brute-force de l'espace opaque (on ne devine pas un ObjectId).
"""
import re
from urllib.parse import parse_qsl, urlsplit

# --- Bornes éditables ---------------------------------------------------------
OPAQUE_MIN = 16     # longueur mini d'un token opaque (base64/hex) pour être un id-candidat
POOL_CAP = 500      # cap dur du pool récolté (borné)
SEQ_DELTA = 5       # +/- autour d'un id numérique découvert (génération séquentielle bornée)
SEQ_CAP = 40        # cap dur du nombre d'ids séquentiels générés

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_OPAQUE_RE = re.compile(r"[A-Za-z0-9+/_=-]{%d,}" % OPAQUE_MIN)   # base64/hex/urlsafe long


def _classe_opaque(t):
    """Classe de caractères d'un token opaque (pour matcher même alphabet)."""
    if re.fullmatch(r"[0-9a-fA-F]+", t):
        return "hex"
    if any(c in t for c in "+/="):
        return "b64"
    if any(c in t for c in "-_"):
        return "b64url"
    return "alnum"


def shape_of(token):
    """Signature GÉNÉRIQUE (type, longueur, classe) d'un token, ou None si non id-like.
    C'est la clé de matching : deux tokens « de même nature » ont la même shape."""
    t = (token or "").strip()
    if not t:
        return None
    if _UUID_RE.fullmatch(t):
        return ("uuid", 36, "hex-dash")
    if re.fullmatch(r"[0-9a-f]{24}", t):
        return ("objectid", 24, "hex")
    if t.isdigit():
        return ("num", len(t), "num")
    if (len(t) >= OPAQUE_MIN and re.fullmatch(r"[A-Za-z0-9+/_=-]+", t)
            and any(c.isdigit() for c in t) and any(c.isalpha() for c in t)):
        return ("opaque", len(t), _classe_opaque(t))
    return None


def extraire(text):
    """Récolte les tokens id-like d'un TEXTE (corps déjà capturé). -> {token: shape}.
    Scanne uuid + tokens opaques/hex/objectid (>= OPAQUE_MIN). Les numériques courts
    ne sont PAS scannés dans les corps (trop de bruit) : ils viennent des params
    d'URL et de la génération séquentielle."""
    toks = {}
    for rx in (_UUID_RE, _OPAQUE_RE):
        for m in rx.finditer(text or ""):
            s = shape_of(m.group())
            if s:
                toks[m.group()] = s
    return toks


def extraire_params(url):
    """Récolte les valeurs id-like des SEGMENTS de chemin et des PARAMS d'une URL
    découverte. -> {token: shape} (inclut les numériques, qui sont des ids légitimes ici)."""
    toks = {}
    parts = urlsplit(url or "")
    for seg in parts.path.split("/"):
        s = shape_of(seg)
        if s:
            toks[seg] = s
    for _, v in parse_qsl(parts.query, keep_blank_values=True):
        s = shape_of(v)
        if s:
            toks[v] = s
    return toks


class Pool:
    """Pool BORNÉ des ids récoltés, taggés {shape, sources}. Cap dur POOL_CAP."""

    def __init__(self, cap=POOL_CAP):
        self.cap = cap
        self._d = {}   # token -> {"shape": tuple, "sources": set}

    def ajouter(self, token, shape, source):
        if token in self._d:
            self._d[token]["sources"].add(source)
            return
        if len(self._d) >= self.cap:
            return  # borné : on n'explose pas
        self._d[token] = {"shape": shape, "sources": {source}}

    def ingerer_texte(self, text, source):
        for tok, shape in extraire(text).items():
            self.ajouter(tok, shape, source)

    def ingerer_url(self, url):
        for tok, shape in extraire_params(url).items():
            self.ajouter(tok, shape, "url:" + url)

    def par_shape(self, shape):
        return [t for t, m in self._d.items() if m["shape"] == shape]

    def shapes(self):
        from collections import Counter
        return Counter(tuple(m["shape"]) for m in self._d.values())

    def __len__(self):
        return len(self._d)


def match_feed(shape_cible, pool, deja):
    """Ids récoltés de la MÊME shape que l'endpoint cible, qu'il n'a PAS déjà.
    Match = (type, longueur, classe) identiques. Candidats EN PLUS, jamais un
    dépassement de budget (le plafond de requêtes reste chez la sonde)."""
    deja = set(deja or [])
    return [t for t in pool.par_shape(tuple(shape_cible)) if t not in deja]


def sequentiel(ids_numeriques, delta=SEQ_DELTA, cap=SEQ_CAP):
    """Génération SÉQUENTIELLE bornée autour des ids numériques DÉCOUVERTS (range
    +/- delta, capé). Renvoie les nouveaux ids seulement. Ce n'est PAS du brute-force
    d'espace opaque : borné, autour du connu, uniquement pour les ids numériques."""
    connus = set(str(i) for i in ids_numeriques)
    out = set()
    for idv in ids_numeriques:
        try:
            n = int(idv)
        except (TypeError, ValueError):
            continue
        for d in range(-delta, delta + 1):
            if n + d >= 0:
                out.add(str(n + d))
    out -= connus
    return sorted(out, key=int)[:cap]
