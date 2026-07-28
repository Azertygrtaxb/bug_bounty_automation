"""Signaux de scoring — CONNAISSANCE métier, séparée du moteur.

Chaque signal = (nom, test, poids). Un signal AUGMENTE le score, il ne retire
jamais rien (ça, c'est le rôle du gate). Le score est une simple somme
pondérée linéaire : lisible et débogable.

Deux formes de test, gérées par evaluer() :
  - BOOLÉEN : test -> True/False, poids FIXE pris dans le tuple.
  - GRADUÉ  : test -> int (0 = absent, sinon le poids). Le tuple porte None :
              le poids est décidé DANS la fonction (gradation intra-signal).
              Aucune hiérarchie entre signaux différents n'est introduite ici,
              seulement de la nuance À L'INTÉRIEUR d'un même signal.

    test(target) -> bool | int
    target = {
        "url": str, "host": str, "http_status": int|None,
        "tech": list[str], "tags": dict,
    }

Purement déterministe (même target -> même sortie). Aucune IA, aucun réseau.

>>> Édite librement les POIDS (dans la liste SIGNAUX pour les booléens, dans les
    fonctions graduées pour les autres) : c'est fait pour ça.
"""
import re
from urllib.parse import parse_qsl, urlencode, urlsplit

from knowledge.dedup import PLACEHOLDERS
from knowledge.substance import (ERROR_RETURN_PARAMS, OPEN_REDIRECT_BONUS,
                                 is_canonical_redirect, is_error_page, is_malformed,
                                 is_param_driven_redirect)

# --- Motifs compilés une fois -------------------------------------------------
_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
_UUID_ANY = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)
_ID_PARAM_KEYS = {
    "id", "uid", "uuid", "guid", "account", "accountid", "customer", "customerid",
    "contract", "contractid", "user", "userid", "member", "memberid", "order",
    "orderid", "invoice", "invoiceid", "doc", "docid", "file", "fileid",
    "num", "no", "cat", "pid",
}
_OPAQUE = re.compile(r"^[A-Za-z0-9._~+/=-]{8,}$")  # base64/hex/jwt-ish, non purement numérique

# --- Récupération d'objet par id sur une API (BOLA/IDOR) -----------------------
# "/api/" est une convention générique (pas host-spécifique). Un id sur ce chemin =
# récupération d'objet par référence : cible de première classe, INDÉPENDAMMENT de la
# devinabilité (une référence fuitée n'a pas besoin d'énumération ; un ObjectId n'est
# pas opaque-sûr). Poids éditable, s'ADDITIONNE à id_non_derive_session.
_API_PATH = re.compile(r"/api/", re.IGNORECASE)
API_OBJET_PAR_ID = 5

# --- Motifs de flux d'authentification (éditable). Couvre les séparateurs
# courants (sign_up / sign-up / signup) pour ne pas rater une surface "vuln clé"
# comme la création de compte. Cherché dans le chemin ET dans le title.
AUTH_MOTIFS = [
    "login", "log-in", "logon", "logout", "signin", "sign-in", "sign_in",
    "signup", "sign-up", "sign_up", "register", "registration", "inscription",
    "create-account", "create_account", "createaccount", "compte",
    "password", "passwd", "password-reset", "password_reset",
    "reset-password", "reset_password", "forgot-password", "forgot_password",
    "motdepasse", "mot-de-passe", "reset", "refresh", "token",
    "oauth", "sso", "saml", "auth", "authorize", "authorization",
    "authentification", "authentication",
    "connexion", "connect", "mfa", "otp", "session", "activate", "activation",
]
# "signin" est borné à droite (?![a-z]) pour tuer le faux positif "SignInv"
# (Sign Invoice) sans casser "/signin", "sign-in", etc.
_AUTH = re.compile("|".join(
    (re.escape(m) + r"(?![a-z])") if m in ("signin", "sign-in", "sign_in") else re.escape(m)
    for m in AUTH_MOTIFS), re.IGNORECASE)
_ARGENT = re.compile(
    r"(virement|payment|paiement|transfer|transaction|montant|amount|iban|wire"
    r"|fund|payout|invoice|refund|solde|balance|checkout|order)",
    re.IGNORECASE,
)
_VERB_STATE = re.compile(
    r"(delete|remove|update|create|add|edit|save|set|enable|disable|activate"
    r"|deactivate|revoke|grant|approve|cancel|drop|upload|import|export)",
    re.IGNORECASE,
)

# Surface exposée, par gravité décroissante (le premier motif qui matche gagne).
_SURFACE_TIERS = [
    (re.compile(
        r"(/\.git|/\.env|/\.aws|/id_rsa|/actuator/env|/actuator/heapdump"
        r"|/actuator/threaddump|/actuator/mappings|/credentials|/secrets)",
        re.IGNORECASE), 8),
    (re.compile(r"(/actuator|/metrics|/debug|/console|/api/dev|/dev/)", re.IGNORECASE), 5),
    (re.compile(r"(swagger|openapi|graphql|graphiql)", re.IGNORECASE), 3),
]

# --- Produits à surface d'attaque connue (LU dans tech[]/title, pas l'URL) -----
# Motif en minuscules -> poids. Cherché dans les technos détectées par httpx et
# dans le title de la page. Éditable : ajoute un produit/console/gateway.
# Ce sont des FAITS mécaniques (tel produit détecté), pas du jugement de valeur.
PRODUITS = {
    # Appliances edge / gateways d'auth (bugs connus à fort impact)
    "f5 bigip": 8, "big-ip": 8,
    "citrix": 8, "netscaler": 8,
    "fortinet": 8, "fortigate": 8, "forticlient": 8,
    "pulse secure": 8, "ivanti": 8,
    "globalprotect": 8, "palo alto": 8,
    "adfs": 7, "keycloak": 6, "cas ": 6,
    # Consoles d'admin / interfaces de gestion
    "tomcat": 6, "jboss": 6, "weblogic": 7, "websphere": 6,
    "jenkins": 7, "phpmyadmin": 7, "kibana": 6, "grafana": 5,
    "gitlab": 6, "jira": 5, "confluence": 6, "sharepoint": 5,
    "outlook web app": 6, "owa": 6, "exchange": 5,
}

# --- Extensions d'assets statiques : ne déclenchent PAS les signaux de mots-clés
# Éditable. auth.js / style.css / logo.png ne sont pas des endpoints applicatifs.
ASSET_EXTENSIONS = {
    "js", "mjs", "css", "scss", "less", "map",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp",
    "woff", "woff2", "ttf", "eot", "otf",
    "mp4", "webm", "mp3", "wav", "pdf",
}
_ASSET_RE = re.compile(
    r"\.(" + "|".join(sorted(ASSET_EXTENSIONS)) + r")(?:$|[?#])", re.IGNORECASE
)

# --- Répertoires d'assets : un segment de chemin ici => contenu servi, pas la
# surface applicative. Éditable.
ASSET_DIRS = {
    "public", "static", "assets", "images", "img", "media", "medias",
    "download", "downloads", "css", "js", "scripts", "styles", "fonts", "content",
    "pdf", "pdfs",
}

# --- Pages statiques informationnelles (mentions légales / cookies / privacy) :
# quasi-assets, non éligibles aux signaux métier. Motifs éditables.
STATIC_INFO_PATTERNS = [
    "mentions_legales", "mentions-legales", "mentionslegales", "legal", "disclaimer",
    "cookie", "privacy", "confidentialite", "politique", "conditions", "terms",
    "cgu", "cgv", "accessibilite",
]
_STATIC_INFO_RE = re.compile("|".join(STATIC_INFO_PATTERNS), re.IGNORECASE)

# --- Chemins-signature d'un produit : LA surface d'attaque réelle (portail,
# console), par famille. Éditable. Un endpoint dont le chemin matche => plein
# tarif du fingerprint ; sinon => résidu faible (le host tourne le produit, mais
# ce chemin n'est pas une route produit).
CHEMINS_SIGNATURE_PRODUIT = {
    "f5":       [r"/my\.policy", r"/my\.logout", r"/vdesk", r"/tmui", r"/mrhinc",
                 r"/xui", r"/icontrol", r"/f5-w", r"/trafficshield"],
    "citrix":   [r"/vpn/", r"/citrix/", r"/logon/", r"/cgi/", r"/nf/auth", r"/netscaler"],
    "fortinet": [r"/remote/login", r"/remote/fgt_lang", r"/sslvpn"],
    "ivanti":   [r"/dana-na/", r"/dana/"],
    "paloalto": [r"/global-protect", r"/ssl-vpn", r"/php/logins"],
}
# Rattache chaque motif de PRODUITS à une famille de signatures ci-dessus.
_PRODUIT_FAMILLE = {
    "f5 bigip": "f5", "big-ip": "f5",
    "citrix": "citrix", "netscaler": "citrix",
    "fortinet": "fortinet", "fortigate": "fortinet", "forticlient": "fortinet",
    "pulse secure": "ivanti", "ivanti": "ivanti",
    "globalprotect": "paloalto", "palo alto": "paloalto",
}
_SIG_COMPILED = {
    fam: [re.compile(p, re.IGNORECASE) for p in motifs]
    for fam, motifs in CHEMINS_SIGNATURE_PRODUIT.items()
}
# Facteur appliqué au poids produit sur un chemin NON-signature (host qui tourne
# le produit, mais endpoint quelconque). Éditable.
FINGERPRINT_RESIDU_DIVISEUR = 4

# --- Politique de statut HTTP : facteur multiplicatif du score final. Éditable.
# Un endpoint MORT (404/410) n'est pas une cible, quels que soient ses signaux :
# un id séquentiel sur une route morte ne vaut rien.
STATUT_FACTEURS = {
    "vivant": 1.0,    # 200 / 3xx / 401 / 403 : présent (ou muré mais bien là)
    "casse":  0.25,   # 5xx : le host répond mais l'endpoint est cassé
    "mort":   0.0,    # 404 / 410 : route morte
    "inconnu": 1.0,   # pas de statut connu : on ne pénalise pas par défaut
}


def facteur_statut(status):
    """Facteur [0..1] appliqué au score selon le statut HTTP observé."""
    if status is None:
        return STATUT_FACTEURS["inconnu"]
    if status in (404, 410):
        return STATUT_FACTEURS["mort"]
    if 500 <= status <= 599:
        return STATUT_FACTEURS["casse"]
    if status in (200, 401, 403) or 300 <= status <= 399:
        return STATUT_FACTEURS["vivant"]
    return STATUT_FACTEURS["inconnu"]


def _url(t):
    return t.get("url") or ""


def _path_query(t):
    """Chemin + requête seulement (exclut host et schéma).

    Empêche un signal de matcher par hasard le NOM DE DOMAINE — ex. le host
    « einvoice.bpce-vietnam.com » contient « invoice », ce qui déclenchait
    faussement mouvement_argent sur tout le host. On teste ce que la cible
    EXPOSE (le chemin), pas comment elle s'appelle."""
    p = urlsplit(_url(t))
    return f"{p.path}?{p.query}" if p.query else (p.path or "")


def _haystack_brut(t):
    """Chemin + requête, casse préservée, débarrassé (a) du FQDN recopié dans le
    chemin et (b) des paramètres de type erreur/retour (aspxerrorpath, ReturnUrl,
    sourceURL...) dont la VALEUR est une route réfléchie, pas la page elle-même."""
    p = urlsplit(_url(t))
    pairs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
             if k.lower() not in ERROR_RETURN_PARAMS and v.lower() not in PLACEHOLDERS]
    q = urlencode(pairs)
    text = f"{p.path}?{q}" if q else (p.path or "")
    if p.hostname:
        text = re.sub(re.escape(p.hostname), "", text, flags=re.IGNORECASE)
    return text


def _signal_haystack(t):
    """Version minuscule de _haystack_brut, base des signaux de mots-clés."""
    return _haystack_brut(t).lower()


def _is_asset(t):
    """True si l'URL pointe un asset statique par son EXTENSION (.js/.css/.png...)."""
    return bool(_ASSET_RE.search(urlsplit(_url(t)).path))


def _is_asset_dir(t):
    """True si un segment du chemin est un répertoire d'assets (/public/, /static/,
    /images/, /download/...) : contenu servi, pas la surface applicative."""
    segs = (s.lower() for s in urlsplit(_url(t)).path.split("/") if s)
    return any(s in ASSET_DIRS for s in segs)


def _is_static_info(t):
    """True si le chemin est une page informationnelle (mentions légales, cookies,
    privacy, CGU...) : quasi-asset, hors surface applicative."""
    return bool(_STATIC_INFO_RE.search(urlsplit(_url(t)).path))


def _hors_surface(t):
    """Asset statique (extension) ou page informationnelle : hors de la surface
    applicative, donc non éligible aux signaux de mots-clés."""
    return _is_asset(t) or _is_static_info(t)


# --- Année ≠ id : un segment de chemin de 4 chiffres dans une plage-année plausible
# est une ANNÉE (/insurance-products/2019, /partage/2018/...), pas un id court.
# Éditable §0.4. Un 4-chiffres HORS plage (ex. 4217) reste un id plein.
ANNEE_MIN, ANNEE_MAX = 1990, 2035
ANNEE_POIDS = 0

# --- Timestamp / cache-buster ≠ id : un segment numérique nu trop grand pour un id
# plausible (>= TIMESTAMP_MIN_DIGITS chiffres OU valeur > MAX_ID_PLAUSIBLE) est un
# timestamp Unix / cache-buster (Moodle /lib/requirejs.php/1772700809/...), pas un id.
# Un id numérique réaliste (< seuil) reste un id plein. Éditable §0.4.
TIMESTAMP_MIN_DIGITS = 10
MAX_ID_PLAUSIBLE = 1_000_000_000
TIMESTAMP_POIDS = 0


def _est_annee_chemin(seg):
    return len(seg) == 4 and seg.isdigit() and ANNEE_MIN <= int(seg) <= ANNEE_MAX


def _est_timestamp(seg):
    return seg.isdigit() and (len(seg) >= TIMESTAMP_MIN_DIGITS or int(seg) > MAX_ID_PLAUSIBLE)


def _poids_num_chemin(seg):
    """Poids d'un segment de chemin numérique : année/timestamp neutralisés, sinon id."""
    if _est_annee_chemin(seg):
        return ANNEE_POIDS
    if _est_timestamp(seg):
        return TIMESTAMP_POIDS
    return _num_weight(seg)


# --- Tests des signaux --------------------------------------------------------
def _num_weight(value):
    """id numérique court (devinable/séquentiel) plus grave que long."""
    return 6 if len(value) <= 4 else 5


def id_non_derive_session(t):
    """GRADUÉ. Identifiant manipulable dans l'URL, nuancé par sa devinabilité :
    numérique court +6 > numérique long +5 > UUID +3 > valeur opaque/signée +1.
    Renvoie le poids max parmi les identifiants trouvés (0 si aucun).

    Un chiffre dans un répertoire d'assets (/fonts/58, /pdfs/52) n'est PAS un
    identifiant applicatif : ces chemins sont exclus."""
    if _is_asset(t) or _is_asset_dir(t):
        return 0
    parts = urlsplit(_url(t))
    best = 0

    # Segments de chemin purement numériques : /account/42
    # (ANNÉE nue et TIMESTAMP/cache-buster neutralisés ; un id réaliste reste un id)
    for seg in parts.path.split("/"):
        if seg.isdigit():
            best = max(best, _poids_num_chemin(seg))
    # UUID n'importe où dans le chemin ou la requête
    if _UUID_ANY.search(parts.path) or _UUID_ANY.search(parts.query):
        best = max(best, 3)
    # Paramètres de requête qui désignent un identifiant : customerId=, id=...
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        kl = key.lower()
        if not (kl in _ID_PARAM_KEYS or kl.endswith("_id") or kl == "id"):
            continue
        if value.isdigit():
            best = max(best, _num_weight(value))
        elif _UUID.match(value):
            best = max(best, 3)
        elif value and _OPAQUE.match(value):
            best = max(best, 1)  # valeur opaque / signée : peu manipulable
    return best


def api_objet_par_id(t):
    """BOOLÉEN. Un identifiant sur un chemin /api/ = récupération d'objet par
    référence => surface BOLA/IDOR de première classe, INDÉPENDAMMENT de la
    devinabilité de l'id. Signal de PRIORITÉ : monte la cible, ne conclut rien —
    le corps stocké dira ensuite si l'API rend de la donnée possédée ou du public.
    S'ADDITIONNE à id_non_derive_session (la gradation numérique/séquentielle y reste,
    donc un id devinable reste plus fort). Assets exclus."""
    if _hors_surface(t):
        return False
    parts = urlsplit(_url(t))
    if not _API_PATH.search(parts.path):
        return False
    # id dans un segment de chemin (/api/users/123, /api/.../{uuid})
    for seg in parts.path.split("/"):
        if seg.isdigit() or _UUID_ANY.search(seg):
            return True
    # id en paramètre de requête (?id=..., ?documentId=...), valeur non vide
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        kl = key.lower()
        if value and (kl in _ID_PARAM_KEYS or kl.endswith("_id") or kl == "id"):
            return True
    return False


def fingerprint_produit(t):
    """GRADUÉ. Croise le PRODUIT détecté (dans tech[]/title, pas l'URL) avec la
    NATURE du chemin — le fingerprint ne s'applique plus à l'identique à tout le host :

      - asset (extension/répertoire) ou page statique servie derrière le produit
        => 0 (un .js ou une image derrière F5 n'est pas la surface F5) ;
      - chemin = route-signature du produit (my.policy, /vdesk/, /vpn/...)
        => plein tarif ;
      - produit détecté mais chemin quelconque => résidu faible (host qui tourne
        le produit, mais endpoint non caractéristique).
    """
    tags = t.get("tags") or {}
    hay = " ".join(t.get("tech") or [])
    hay = f"{hay} {tags.get('title') or ''}".lower()
    matches = [(motif, poids) for motif, poids in PRODUITS.items() if motif in hay]
    if not matches:
        return 0
    motif, poids = max(matches, key=lambda mp: mp[1])

    # Asset / page statique servi derrière le produit ≠ surface du produit.
    if _is_asset(t) or _is_asset_dir(t) or _is_static_info(t):
        return 0

    # Chemin = route-signature du produit détecté -> plein tarif.
    path = urlsplit(_url(t)).path.lower()
    famille = _PRODUIT_FAMILLE.get(motif)
    for motif_sig in _SIG_COMPILED.get(famille, []):
        if motif_sig.search(path):
            return poids

    # Produit connu, chemin non-signature -> résidu faible.
    return max(1, poids // FINGERPRINT_RESIDU_DIVISEUR)


def flux_auth(t):
    """BOOLÉEN. Flux d'authentification : login/logout/register/reset/token...
    Cherché dans le chemin+requête ET dans le title : un portail de login peut
    avoir un chemin muet (login à la racine /) mais un title parlant
    (« Authentification », « Connexion », « Sign in »). Assets exclus."""
    if _hors_surface(t):
        return False
    if _AUTH.search(_signal_haystack(t)):
        return True
    title = (t.get("tags") or {}).get("title") or ""
    return bool(_AUTH.search(title))


def mouvement_argent(t):
    """BOOLÉEN. Logique métier à enjeu : virement/payment/transfer/montant/amount...
    Testé sur le chemin+requête (host retiré) ; les assets statiques sont exclus."""
    if _hors_surface(t):
        return False
    return bool(_ARGENT.search(_signal_haystack(t)))


def surface_exposee(t):
    """GRADUÉ. Surface technique exposée, nuancée par gravité :
    fuite critique (/.git, /.env, /actuator/env...) +8 > interne (/actuator,
    /metrics, /debug...) +5 > doc d'API (swagger/openapi/graphql) +3.
    Renvoie le poids du palier le plus grave (0 si aucun)."""
    u = _path_query(t)
    return max((poids for motif, poids in _SURFACE_TIERS if motif.search(u)), default=0)


def verbe_state_changing_en_GET(t):
    """BOOLÉEN. Un verbe qui modifie l'état, atteignable en GET (recon passif =
    GET) : signal de faible auth / sensibilité CSRF. Chemin+requête, host retiré ;
    les assets statiques sont exclus."""
    if _hors_surface(t):
        return False
    return t.get("http_status") is not None and bool(_VERB_STATE.search(_signal_haystack(t)))


# --- La liste éditable : (nom, test, poids) -----------------------------------
# poids = int pour un signal BOOLÉEN ; None pour un signal GRADUÉ (poids interne).
SIGNAUX = [
    ("fingerprint_produit",         fingerprint_produit,         None),
    ("id_non_derive_session",       id_non_derive_session,       None),
    ("api_objet_par_id",            api_objet_par_id,            API_OBJET_PAR_ID),
    ("flux_auth",                   flux_auth,                   5),
    ("mouvement_argent",            mouvement_argent,            5),
    ("surface_exposee",             surface_exposee,             None),
    ("verbe_state_changing_en_GET", verbe_state_changing_en_GET, 2),
]


def evaluer(target):
    """Applique tous les signaux -> (score:int, raisons:list[str]).

    Somme pondérée linéaire. Un signal booléen déclenché ajoute le poids fixe du
    tuple ; un signal gradué ajoute le poids qu'il renvoie. La raison d'un signal
    gradué porte sa contribution — « id_non_derive_session(+6) » — pour rendre la
    pente lisible ; un booléen garde son nom nu.

    Enfin, le score est modulé par le STATUT HTTP : un endpoint mort (404/410)
    tombe à 0 quels que soient ses signaux, un 5xx est fortement réduit. La
    pénalité laisse une raison visible (« statut_404(x0.0) »)."""
    score = 0
    raisons = []
    for nom, test, poids in SIGNAUX:
        res = test(target)
        if res is True:              # booléen déclenché -> poids fixe
            score += poids
            raisons.append(nom)
        elif isinstance(res, bool):  # booléen False -> rien
            continue
        elif isinstance(res, int) and res > 0:  # gradué -> poids renvoyé
            score += res
            raisons.append(f"{nom}(+{res})")

    # Modulation par le statut HTTP (un id mort n'est pas une cible).
    status = target.get("http_status")
    facteur = facteur_statut(status)
    if score > 0 and facteur < 1.0:
        score = round(score * facteur)
        raisons.append(f"statut_{status}(x{facteur})")

    # --- Démotion consciente de la RÉPONSE (substance) ------------------------
    # Un endpoint qui a des signaux mais dont la réponse est un shell catch-all
    # ou une page d'erreur est du bruit : on l'écrase à 0, raison tracée.
    url = _url(target)
    fh_status = target.get("first_hop_status")
    fh_location = target.get("first_hop_location")

    # Signal bonus : redirection premier-hop PILOTÉE par un paramètre = candidat
    # open redirect. On FLAGGE (jamais démoté), même si le score de base est 0.
    if fh_location and is_param_driven_redirect(url, fh_location):
        raisons.append("open_redirect_possible")
        score += OPEN_REDIRECT_BONUS

    if score > 0:
        if is_malformed(url, target.get("body_len")):
            raisons.append("url_malformee")
            score = 0
        elif "open_redirect_possible" in raisons:
            pass  # garde-fou : NE démote pas une redirection pilotée par param
        elif is_canonical_redirect(fh_status, url, fh_location, target.get("host")):
            raisons.append("redirect_canonique")
            score = 0
        elif target.get("is_catchall"):
            n = target.get("catchall_n")
            raisons.append("catch-all: body partage par %s endpoints du host" % (n if n else "N"))
            score = 0
        elif is_error_page(status, (target.get("tags") or {}).get("title"),
                           target.get("body_len")):
            raisons.append("page_erreur")
            score = 0
    return score, raisons
