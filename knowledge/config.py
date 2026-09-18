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

# --- Rush : attente des tâches Celery (_wait_all). Le timeout s'ADAPTE au parc — sur 48k
# hosts un plafond fixe décrocherait au bout de 40 min et le classement serait calculé sur
# un tier 1 partiel (silencieusement FAUX). Éditable §14.
TIMEOUT_PAR_TACHE = int(os.environ.get("TIMEOUT_PAR_TACHE", "20"))  # s alloués par tâche
TIMEOUT_MIN = int(os.environ.get("TIMEOUT_MIN", "2400"))            # plancher (s)
PROGRESS_SECS = int(os.environ.get("PROGRESS_SECS", "60"))          # cadence des lignes de progression
# Agrégation (score_targets / rebuild_leads) : plancher + terme ∝ nombre de lignes de targets.
TIMEOUT_AGREGATION_MIN = int(os.environ.get("TIMEOUT_AGREGATION_MIN", "1800"))
TIMEOUT_AGREGATION_PAR_1000 = int(os.environ.get("TIMEOUT_AGREGATION_PAR_1000", "20"))  # s / 1000 lignes
# Sortie bornée : n'imprime que le top N du classement ; listes complètes -> fichier.
AFFICHAGE_RANG_MAX = int(os.environ.get("AFFICHAGE_RANG_MAX", "40"))

# --- Ordre d'avancement d'un statut (dernier = le plus avancé). Sert à résoudre une
# COLLISION quand deux leads statutés se replient sur le même pattern : le plus avancé
# gagne, les notes sont concaténées (jamais perdre du travail humain).
ORDRE_STATUT = ["a_voir", "en_cours", "tue", "rapporte"]

# --- Collapse : garde-fous BOLA -----------------------------------------------
# B1 : ne JAMAIS replier un segment immédiatement suivi d'un {id}/{annee} — c'est le
# TYPE D'OBJET (/api/user/{id} vs /api/order/{id}), la cible BOLA elle-même, pas du bruit.
REPLIER_SEGMENT_AVANT_ID = os.environ.get("REPLIER_SEGMENT_AVANT_ID", "0").lower() in ("1", "true", "yes", "on")
# B2 : ne replier une famille que si ses membres ont le MÊME profil de signal. C4 : la
# comparaison EXACTE (score + chaînes de raisons) était trop stricte — une nuance de poids
# (host_vieux_copyright(+2) vs (+3)) rendait des frères hétérogènes. On compare désormais les
# FAMILLES de signaux (noms sans pondérations) et on tolère un écart de score ECART_COLLAPSE_MAX.
COLLAPSE_EXIGE_MEME_PROFIL = os.environ.get("COLLAPSE_EXIGE_MEME_PROFIL", "1").lower() in ("1", "true", "yes", "on")
ECART_COLLAPSE_MAX = int(os.environ.get("ECART_COLLAPSE_MAX", "2"))

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

# --- Vue groupée par host : au-delà de ce nombre de leads dans UN groupe déplié, l'UI
# n'en affiche d'abord que les mieux scorés + un bouton « voir les N restants » (pagination
# d'affichage, pas un masquage — la donnée est déjà chargée). Éditable §14.
AFFICHAGE_MAX_LEADS_PAR_GROUPE = int(os.environ.get("AFFICHAGE_MAX_LEADS_PAR_GROUPE", "50"))

# --- Couche sémantique (juge LLM AVEUGLE sur le corps déjà stocké) ------------------
# Le sémantique REPÊCHE le résidu (score bas) que le déterministe ne voit pas ; il ne
# démote pas (sauf 'institutionnel', dépriorisation bornée). Plafonné pour ne jamais
# passer devant un vrai signal déterministe. AUCUNE requête réseau vers les cibles.
MODELE_JUGE = os.environ.get("MODELE_JUGE", "claude-sonnet-5")
EFFORT_JUGE = os.environ.get("EFFORT_JUGE", "low")
EXTRAIT_JUGE_MAX = int(os.environ.get("EXTRAIT_JUGE_MAX", "2500"))   # coût n°1 : le corps pèse 10x la réponse ; 2500 suffit à classer la NATURE (mur d'auth/API/narratif visibles tôt)
SEUIL_RESIDU = int(os.environ.get("SEUIL_RESIDU", "4"))             # on ne juge que score 0..SEUIL_RESIDU
ECHANTILLON_SEM = int(os.environ.get("ECHANTILLON_SEM", "300"))
MAX_APPELS_JUGE_PAR_RUN = int(os.environ.get("MAX_APPELS_JUGE_PAR_RUN", "300"))  # plafond dépense côté code
BONUS_APPLICATIF = int(os.environ.get("BONUS_APPLICATIF", "3"))
BONUS_SURFACE_AUTH = int(os.environ.get("BONUS_SURFACE_AUTH", "2"))
PLAFOND_SEM = int(os.environ.get("PLAFOND_SEM", "5"))              # garde-fou dur : plafond après bonus sémantique
# Attente du batch LLM dans rush : NON dérivée du parc (le batch dure indépendamment du
# nombre de lignes). Plafond dur pour ne pas bloquer un rush indéfiniment sur l'API.
TIMEOUT_JUGE_SEM = int(os.environ.get("TIMEOUT_JUGE_SEM", "3600"))  # 1h : couvre un batch Anthropic lent

# --- Juge V2 : classification de SURFACE des représentants visibles dans Leads -------
# V2 ne touche pas au score déterministe : il fournit à l'humain une lecture explicable
# (surface + indices + confiance) avant l'envoi manuel vers Operations. Le lot initial est
# volontairement plus petit que V1 afin de calibrer les sorties sur les vrais findings avant
# toute hausse de dépense.
MODELE_JUGE_V2 = os.environ.get("JUGE_V2_MODELE", MODELE_JUGE)
EFFORT_JUGE_V2 = os.environ.get("JUGE_V2_EFFORT", EFFORT_JUGE)
EXTRAIT_JUGE_V2_MAX = int(os.environ.get("JUGE_V2_EXTRAIT_MAX", str(EXTRAIT_JUGE_MAX)))
JUGE_V2_MIN_SCORE = int(os.environ.get("JUGE_V2_MIN_SCORE", "8"))
JUGE_V2_ECHANTILLON = int(os.environ.get("JUGE_V2_ECHANTILLON", "100"))
JUGE_V2_MAX_APPELS = int(os.environ.get("JUGE_V2_MAX_APPELS", "100"))

# --- Anti-bruteforce du login board : au-delà de BOARD_MAX_ECHECS tentatives ratées par
# (compte, IP) dans BOARD_FENETRE_ECHECS secondes -> 429, sans comparer le mot de passe.
BOARD_MAX_ECHECS = int(os.environ.get("BOARD_MAX_ECHECS", "5"))
BOARD_FENETRE_ECHECS = int(os.environ.get("BOARD_FENETRE_ECHECS", "300"))

# --- Proxies de confiance (E3) : seules ces IP/CIDR peuvent fixer X-Forwarded-For. Défaut
# = réseaux privés (le board est joint par Caddy sur le réseau Docker interne). Un client
# DIRECT hors de ces plages voit son XFF IGNORÉ (l'en-tête est trivialement falsifiable).
PROXIES_DE_CONFIANCE = [c.strip() for c in os.environ.get(
    "PROXIES_DE_CONFIANCE",
    "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",") if c.strip()]


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
