"""Gate déterministe — mécanique, jamais de jugement IA.

Règles :

  1. Déduplication — DÉJÀ appliquée à l'insertion via la contrainte UNIQUE
     `hash_dedup` (voir engine/recon/discover.py).

  2. Allowlist de méthodes — seuls GET/HEAD sont autorisés.

  3. CONFINEMENT AU HOST DE LANCEMENT (ligne rouge, non désactivable).
     L'humain fournit le host cible au lancement (il l'a jugé huntable) : la
     sélection in-scope est donc DÉJÀ faite à l'entrée. Le gate ne décide pas ce
     qui est in-scope — il empêche seulement le pipeline de DÉBORDER de cette
     cible. Toute requête ACTIVE (sonde, futures étapes) doit viser le host de
     lancement OU un de ses sous-domaines ; sinon la requête ne part pas.

     (La découverte PASSIVE, elle, peut voir/enregistrer ce qu'elle trouve par
     rebond : c'est de la lecture. Seule l'ACTION est confinée.)

À venir : rate-limit central, barrière d'écriture.
"""
import logging
from urllib.parse import urlsplit

log = logging.getLogger(__name__)

ALLOWED_METHODS = {"GET", "HEAD"}


def is_scannable(target):
    """True si l'endpoint est joignable par une méthode autorisée en lecture.

    La recon passive ne produit que du GET/HEAD ; à défaut d'info de méthode
    dans les tags, on considère GET par défaut."""
    methode = (target.get("tags") or {}).get("methode", "GET")
    return str(methode).upper() in ALLOWED_METHODS


# --- Confinement au host de lancement -----------------------------------------
class HorsCibleError(Exception):
    """Levée quand une requête active viserait un host hors de la cible de
    lancement (autre domaine, tiers atteint par rebond, autre filiale)."""


def _host(url_or_host):
    return urlsplit(url_or_host).hostname if "://" in (url_or_host or "") else url_or_host


def _norm(h):
    return (h or "").lower().strip(".")


def dans_la_cible(host_lancement, url_or_host):
    """True si la cible est le host de lancement ou un de ses sous-domaines."""
    cible = _norm(_host(url_or_host))
    base = _norm(host_lancement)
    return bool(cible) and bool(base) and (cible == base or cible.endswith("." + base))


def confiner(host_lancement, url_or_host):
    """Garde-fou NON désactivable, à appeler AVANT toute requête active.

    Renvoie le host si on reste dans la cible de lancement. Sinon loggue un refus
    explicite et lève HorsCibleError — la requête ne part jamais."""
    if dans_la_cible(host_lancement, url_or_host):
        return _norm(_host(url_or_host))
    log.error("GATE REFUS hors-cible: %s hors du host de lancement '%s' — requete BLOQUEE",
              _host(url_or_host), host_lancement)
    raise HorsCibleError(f"hors cible: {_host(url_or_host)} n'est pas sous {host_lancement}")
