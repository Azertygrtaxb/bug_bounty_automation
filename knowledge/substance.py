"""Demotion consciente de la REPONSE — CONNAISSANCE editable.

Le scoring lit body_hash/body_len (captures a la decouverte) SANS reseau, et
demote ce dont la substance est vide/dupliquee/erreur :
  - CATCH-ALL : un meme body partage par beaucoup d'endpoints d'un host = shell.
  - PAGE D'ERREUR : title/statut d'erreur reconnaissable.
Rien de tout ceci ne juge le SENS (catalogue vs client) — que du mecanique.
"""
import re
from urllib.parse import parse_qsl, unquote, urlsplit

# --- Catch-all / shell --------------------------------------------------------
# Un body_hash partage par >= N endpoints d'un host (ou >= X% du host) = shell.
# On ne compte QUE les corps substantiels (un corps vide n'est pas un shell).
CATCHALL_MIN_ENDPOINTS = 4
CATCHALL_MIN_RATIO = 0.25
CATCHALL_MIN_BODYLEN = 1000

# --- Params de type erreur/retour : leur VALEUR ne caracterise pas la page ----
# Les signaux de mots-cles ne doivent pas matcher dedans (route reflechie).
ERROR_RETURN_PARAMS = {
    "aspxerrorpath", "returnurl", "return_url", "sourceurl", "source_url",
    "redirect", "redirecturl", "redirect_uri", "next", "url", "returnto",
    "return", "dest", "destination", "callback", "continue", "goto",
}

# --- Motifs de page d'erreur (dans le TITLE, dispo au scoring) -----------------
# Specifiques : ne demolissent PAS une vraie surface (une API qui renvoie 400/401
# avec un title applicatif n'est pas matchee ; "Federation - Error" non plus).
ERROR_TITLE_PATTERNS = [
    "potentiallyerror",
    "requ.te bloqu",          # WAF FR "requete bloquee"
    "erreur technique",
    "forbidden", "not found", "access denied", "acc.s refus",
    "service unavailable", "bad gateway", "gateway time",
]
# NB : "Object moved"/"Moved Permanently" NE sont PAS des motifs d'erreur ici —
# un 302 "Object moved" est une redirection vers login sur une VRAIE route
# (surface pre-auth a garder). Les 301 canoniques/marketing sont demotes par la
# regle statut 301 + corps court ci-dessous, sans toucher aux 302.
_ERROR_TITLE = re.compile("|".join(ERROR_TITLE_PATTERNS), re.IGNORECASE)

# Statuts a demoter SEULEMENT si le corps est court/generique (pas une vraie page)
ERROR_STATUS_301_MAXLEN = 600     # 301 permanent a corps quasi nul = redirection canonique
ERROR_STATUS_WAF = {430}          # blocage applicatif type WAF
ERROR_WAF_MAXLEN = 1500


def catchall_hashes(counts):
    """counts: {body_hash: nb_endpoints} (corps substantiels du host uniquement).
    Renvoie l'ensemble des body_hash consideres comme shell/catch-all."""
    total = sum(counts.values())
    out = set()
    for h, n in counts.items():
        if not h:
            continue
        if n >= CATCHALL_MIN_ENDPOINTS or (total and n / total >= CATCHALL_MIN_RATIO):
            out.add(h)
    return out


# --- URLs malformées (artefacts de parsing jsluice, pas de vraies routes) ------
# Critère éditable : backslash littéral ou caractère de contrôle dans le chemin.
# (Le critère « corps vide + content-type absent » nécessiterait de stocker le
#  content-type ; non couvert ici — backslash/contrôle suffit aux cas observés.)
_MALFORMED_PATH = re.compile(r"[\\\x00-\x1f]")


def is_malformed(url, body_len=None):
    """True si l'URL n'est pas une vraie route (chemin avec backslash/contrôle)."""
    from urllib.parse import urlsplit
    return bool(_MALFORMED_PATH.search(urlsplit(url or "").path or ""))


# --- Redirections premier-hop : canonique (démote) vs pilotée-param (flag) ------
# Statuts de redirection permanente considérés « canoniques » si même ressource.
CANONICAL_REDIRECT_STATUS = {301, 308}
# Bonus donné à un candidat open redirect pour le SURFACER (classe de vuln qu'on
# ne voyait pas). Éditable. On flagge, on ne teste rien.
OPEN_REDIRECT_BONUS = 6
# Params dont la valeur peut piloter la destination = candidat OPEN REDIRECT.
REDIRECT_PARAMS = {
    "returnurl", "return_url", "returnto", "return", "redirect", "redirecturl",
    "redirect_uri", "next", "url", "sourceurl", "source_url", "dest",
    "destination", "callback", "continue", "goto", "target", "to",
}


def _same_site(h1, h2):
    h1, h2 = (h1 or "").lower().strip("."), (h2 or "").lower().strip(".")
    return bool(h1) and (h1 == h2 or h1.endswith("." + h2) or h2.endswith("." + h1))


def is_canonical_redirect(first_hop_status, url, location, host):
    """True si le premier-hop est une redirection PERMANENTE vers la MÊME
    ressource sur le MÊME site (seule la forme canonique change : trailing slash,
    casse...). Ce n'est pas une route applicative distincte -> démote.
    GARDE-FOU : cross-host ou chemin différent => PAS canonique."""
    if first_hop_status not in CANONICAL_REDIRECT_STATUS or not location:
        return False
    lu = urlsplit(location)
    if not _same_site(lu.hostname, host):
        return False                          # redirection cross-host : pas canonique
    p_src = (urlsplit(url).path or "").rstrip("/").lower()
    p_dst = (lu.path or "").rstrip("/").lower()
    return p_src == p_dst                      # même ressource, forme canonique


def is_param_driven_redirect(url, location):
    """True si la destination du premier-hop reflète la valeur d'un paramètre de
    redirection de la requête (ReturnUrl, redirect, next, url...) : candidat
    open redirect. On FLAGGE la forme, on ne démote pas, on ne teste rien."""
    if not location:
        return False
    loc = location.lower()
    for key, val in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        if key.lower() not in REDIRECT_PARAMS or not val:
            continue
        v = val.lower()
        if v in loc or unquote(v) in loc or unquote(unquote(v)) in loc:
            return True
    return False


def is_error_page(status, title, body_len):
    """True si la reponse est une page d'erreur reconnaissable (title/statut+taille).
    Volontairement conservateur : ne demote pas une vraie surface qui renvoie une
    erreur applicative (400/401/403 avec title applicatif, 302 vers login...)."""
    if title and _ERROR_TITLE.search(title):
        return True
    if status == 301 and body_len is not None and body_len < ERROR_STATUS_301_MAXLEN:
        return True
    if status in ERROR_STATUS_WAF and (body_len is None or body_len < ERROR_WAF_MAXLEN):
        return True
    return False
