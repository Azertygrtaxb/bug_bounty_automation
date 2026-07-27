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
