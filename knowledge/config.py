"""Config §14 ÉDITABLE — promotion en deep par DEEP_RANK (pas par score shallow seul).

Problème corrigé : un gate « score_shallow >= SEUIL » enterre les hosts
structurellement intéressants que le shallow ne peut pas encore scorer (SPA d'auth
dont les routes n'apparaissent qu'au deep-crawl JS, produit connu, domaine cœur).

DEEP_RANK valorise ces hosts EN AMONT du deep-crawl :
    deep_rank = score_shallow
              + BONUS_SPA      (framework SPA détecté : tech OU bundle hashé)
              + BONUS_PRODUIT  (produit connu détecté : PRODUITS + CMS)
              + BONUS_NOM      (token haute-valeur dans le host OU un chemin shallow)
              + BONUS_CORE     (host sur un domaine cœur in-scope)

Générique : AUCUN host codé en dur. La liste des domaines cœur est de la config de
scope (§14), légitime. Tous les poids et listes ci-dessous sont éditables.
"""
import os
import re

from knowledge.signaux import PRODUITS

# --- Poids (éditables) --------------------------------------------------------
BONUS_SPA = 4
BONUS_PRODUIT = 3
BONUS_NOM = 3
BONUS_CORE = 2

# --- SPA : frameworks (tech) + signature de build hashé (bundle main.<hash>.js) ---
SPA_FRAMEWORKS = {
    "angular", "react", "vue", "svelte", "ember", "backbone", "next.js", "nuxt",
    "preact", "alpine", "knockout", "solid", "stimulus", "riot",
}
_SPA_BUNDLE = re.compile(r"\.[0-9a-f]{8,}\.(?:js|css)\b", re.I)   # artefact de build SPA

# --- Produits connus (réutilise PRODUITS + CMS/frameworks web courants) --------
PRODUITS_CONNUS = {p.lower() for p in PRODUITS} | {
    "wordpress", "moodle", "drupal", "joomla", "magento", "typo3", "sharepoint",
    "asp.net", "microsoft asp.net", "laravel", "django", "spring", "vnpt",
}

# --- Tokens haute-valeur (dans le host OU un chemin shallow) -------------------
TOKENS_HAUTE_VALEUR = [
    "auth", "login", "logon", "card", "otp", "mfa", "admin", "api", "account",
    "sso", "saml", "oauth", "oidc", "portal", "connect", "activate", "sign",
    "reset", "register", "session", "token", "password", "credential",
    "payment", "transfer", "virement", "compte",
]
_TOKENS_RE = re.compile(
    r"(?<![a-z])(?:" + "|".join(TOKENS_HAUTE_VALEUR) + r")(?![a-z])", re.I)

# --- Domaines cœur in-scope (config de scope §14, éditable) --------------------
DOMAINES_COEUR = {
    "groupebpce.com", "bpce.fr", "caisse-epargne.fr", "banque-populaire.fr",
    "banquepopulaire.fr", "natixis.com", "creditmaritime.fr",
}


def _is_spa(tech_l, paths):
    if any(f in tech_l for f in SPA_FRAMEWORKS):
        return True
    return any(_SPA_BUNDLE.search(p or "") for p in (paths or []))


def _is_produit(tech_l):
    return any(p in tech_l for p in PRODUITS_CONNUS)


def _is_core(host):
    h = (host or "").lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in DOMAINES_COEUR)


# --- 1b : scope DÉRIVÉ de la liste lancée (voir engine/scope.py) ---------------
# Plus d'allowlist curée à la main : SCOPE_ROOTS est dérivé des registered-domains de
# la liste targets passée au rush et persisté en base (table scope_roots). La vue
# leads filtre dessus. Flag pour tout garder si besoin.
INCLURE_HORS_SCOPE = os.environ.get("INCLURE_HORS_SCOPE", "0").lower() in ("1", "true", "yes", "on")

# --- 1c : collapse généralisé — >= N frères qui ne varient QUE sur UN segment (n'importe
# quelle position) OU QUE sur les valeurs de query -> ce slot replié en {*}. ---
COLLAPSE_PREFIXE_MIN = int(os.environ.get("COLLAPSE_PREFIXE_MIN", "4"))

# --- Statut de triage HUMAIN d'un lead (table leads_statut, jamais truncatée) -----
STATUTS_LEAD = ["a_voir", "en_cours", "tue", "rapporte"]
STATUT_DEFAUT = "a_voir"

# --- Quota de diversité par host DANS LA VUE (0 = illimité). Au-delà, les leads en
# trop sont repliés en UNE ligne « +N autres » : on déprioritise l'affichage, on ne
# supprime jamais (§0.4). Le quota s'applique à la LECTURE ; la table `leads` garde tout.
MAX_LEADS_PAR_HOST = int(os.environ.get("MAX_LEADS_PAR_HOST", "5"))

# --- Ordre d'avancement d'un statut (dernier = le plus avancé). Sert à résoudre une
# COLLISION quand deux leads statutés se replient sur le même pattern : le plus avancé
# gagne, les notes sont concaténées (jamais perdre du travail humain).
ORDRE_STATUT = ["a_voir", "en_cours", "tue", "rapporte"]

# --- Collapse : garde-fous BOLA -----------------------------------------------
# B1 : ne JAMAIS replier un segment immédiatement suivi d'un {id}/{annee} — c'est le
# TYPE D'OBJET (/api/user/{id} vs /api/order/{id}), la cible BOLA elle-même, pas du bruit.
REPLIER_SEGMENT_AVANT_ID = os.environ.get("REPLIER_SEGMENT_AVANT_ID", "0").lower() in ("1", "true", "yes", "on")
# B2 : ne replier une famille que si ses membres ont le MÊME profil de signal (même
# score ET même ensemble de raisons). Profils différents = endpoints différents.
COLLAPSE_EXIGE_MEME_PROFIL = os.environ.get("COLLAPSE_EXIGE_MEME_PROFIL", "1").lower() in ("1", "true", "yes", "on")

# --- Paramètres de PAGINATION : bruit dans la vue leads. Dans patternize() UNIQUEMENT,
# ces clés de query sont normalisées en {*} quelle que soit leur valeur (?page=1/2/3 =>
# une seule famille). À NE PAS confondre avec les params volatils du hash de dédup
# (knowledge/dedup) qui doivent rester intacts. `p` reste HORS de _ID_PARAM_KEYS (trop
# générique pour être scoré comme un id) mais est neutralisé ici.
PARAMS_PAGINATION = {
    "page", "p", "pageno", "pagenum", "offset", "start", "limit",
    "per_page", "from", "size", "num",
}

# --- Dashboard (Tier 4) : longueur max de l'EXTRAIT de corps montré dans le panneau de
# détail (jamais le corps entier dans la page). Éditable §14.
EXTRAIT_CORPS_MAX = int(os.environ.get("EXTRAIT_CORPS_MAX", "2000"))

# --- Anti-bruteforce du login board : au-delà de BOARD_MAX_ECHECS tentatives ratées par
# (compte, IP) dans BOARD_FENETRE_ECHECS secondes -> 429, sans comparer le mot de passe.
BOARD_MAX_ECHECS = int(os.environ.get("BOARD_MAX_ECHECS", "5"))
BOARD_FENETRE_ECHECS = int(os.environ.get("BOARD_FENETRE_ECHECS", "300"))


def deep_rank(score_shallow, tech, host, paths):
    """Renvoie (deep_rank:int, detail:dict). detail expose chaque composante pour
    savoir POURQUOI un host est promu ou non."""
    tech_l = " ".join(tech or []).lower()
    hay = (host or "") + " " + " ".join(paths or [])
    d = {"score_shallow": int(score_shallow or 0)}
    d["bonus_spa"] = BONUS_SPA if _is_spa(tech_l, paths) else 0
    d["bonus_produit"] = BONUS_PRODUIT if _is_produit(tech_l) else 0
    d["bonus_nom"] = BONUS_NOM if _TOKENS_RE.search(hay) else 0
    d["bonus_core"] = BONUS_CORE if _is_core(host) else 0
    d["deep_rank"] = (d["score_shallow"] + d["bonus_spa"] + d["bonus_produit"]
                      + d["bonus_nom"] + d["bonus_core"])
    return d["deep_rank"], d
