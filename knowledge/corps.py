"""Checks MÉCANIQUES sur le CORPS d'une réponse — CONNAISSANCE éditable.

Fonction pure (regex), AUCUN LLM, AUCUN réseau au-delà du fetch déjà fait. Exécutée en
PRÉ-PASSE, avant d'appeler le juge sémantique. Produit un TAG de priorité, jamais une
démotion :

  1a  is_auth_wall  -> le corps rendu est en réalité un mur de login qui n'appartient
                       PAS à cet endpoint (son contenu propre est caché derrière l'auth).
                       Tag `auth_wall` = EXCLURE de la classification sémantique (input
                       invalide pour le juge) ; la vraie nature revient à signaux.py
                       (param/verbe) + à la sonde comportementale.

NB : pas de détecteur générique « fuite de chemins internes » ici — c'est une brique
FUTURE, à mesurer avant. Les leads host-spécifiques (ex. routes internes einvoice) sont
consignés au Lead Board et chassés en intra-host, PAS codés en dur dans le pipeline.

Prototype : exécuté sur le corps déjà fetché au moment du sémantique. En prod, le flag
sera posé à la CAPTURE (recon/probe), sans stocker les corps entiers.
"""
import re
from urllib.parse import urlsplit

# --- Routes d'authentification ------------------------------------------------
# Un <form action=...> ou une Location premier-hop pointant une de ces routes = login.
# Générique (pas de chaîne host-spécifique) : motifs d'auth usuels multi-frameworks.
_AUTH_ROUTE = re.compile(
    r"(?:^|/)(?:"
    r"account/(?:log-?on|log-?off|login|forget-?pass\w*|smartca\w*|send-?active|register)"
    r"|log-?on|log-?in|sign-?in|sign-?on"
    r"|auth(?:orize|entication|entificate)?|dologin"
    r"|sso|saml2?|oidc|oauth2?"
    r")\b",
    re.I,
)

# --- <form action="..."> ------------------------------------------------------
_FORM_ACTION = re.compile(r"<form\b[^>]*\baction\s*=\s*[\"']([^\"']+)[\"']", re.I)


def _norm_path(u):
    """Chemin normalisé (minuscule, sans slash final, sans query) pour comparer."""
    p = urlsplit(u or "").path or u or ""
    p = p.split("?", 1)[0].split("#", 1)[0]
    return ("/" + p.strip("/").lower()) if p.strip("/") else "/"


def _form_action_paths(body):
    return [_norm_path(a) for a in _FORM_ACTION.findall(body or "")]


def is_auth_wall(url, body, first_hop_location=None):
    """1a. True si le corps est un mur de login qui n'appartient PAS à cet endpoint.

    Mécanique : il existe un <form> (ou une redirection premier-hop) vers une route
    d'AUTH dont le chemin DIFFÈRE du chemin propre de l'endpoint, ET l'endpoint ne rend
    aucun formulaire à SON propre chemin, ET son chemin n'est pas lui-même une route
    d'auth. => son contenu propre est caché derrière le mur, input invalide pour le juge.

    Contre-exemples voulus (NON walls) :
      - /Account/LogOn : le form pointe son propre chemin (surface d'auth propre) ;
      - /HomeNoLogin/SearchByFkey : form propre = recherche, le login est une modale."""
    own = _norm_path(url)
    own_is_auth = bool(_AUTH_ROUTE.search(own))
    actions = _form_action_paths(body)

    # forme d'auth ÉTRANGÈRE = action vers une route d'auth != chemin propre
    foreign_auth = [a for a in actions if _AUTH_ROUTE.search(a) and a != own]
    if first_hop_location:
        loc = _norm_path(first_hop_location)
        if _AUTH_ROUTE.search(loc) and loc != own:
            foreign_auth.append(loc)

    renders_self = own_is_auth or any(a == own for a in actions)
    wall = bool(foreign_auth) and not renders_self
    return wall, {"own_path": own, "own_is_auth": own_is_auth,
                  "form_actions": sorted(set(actions)),
                  "foreign_auth": sorted(set(foreign_auth))}
