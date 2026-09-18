"""Sonde comportementale — CONNAISSANCE : garde-fous ROE + seuils de décision.

Le moteur (engine/probe) applique ; ici on ne fait que déclarer les bornes et
les seuils, tous éditables. La sonde compare les réponses de plusieurs id d'un
même pattern (/banque/{id}...) et repriorise. Elle ne conclut JAMAIS « IDOR
confirmé » : elle ajuste un score et écrit une observation. La preuve reste humaine.
"""

# --- Garde-fous ROE (bornes DURES, appliquées mécaniquement par le moteur) ----
METHODES_AUTORISEES = {"GET", "HEAD"}   # jamais d'effet de bord (POST/PUT/DELETE)
MAX_REQUETES_PAR_HOST = 20              # plafond dur de requêtes / host / run
DELAI_ENTRE_REQUETES = 1.0             # secondes entre deux requêtes (throttle)
TIMEOUT_REQUETE = 8                     # secondes par requête
MAX_CORPS_OCTETS = 200_000             # ne pas télécharger de corps géant

# --- Échantillonnage (borné : on ne brute-force pas) --------------------------
TAILLE_ECHANTILLON = 4                  # nb d'id DÉJÀ connus sondés par groupe
SONDER_BORNE = True                     # tester 1 id hors-séquence (borne d'énum)
ID_BORNE = 99_999_999                   # id manifestement hors-séquence

# --- Comparaison déterministe des réponses ------------------------------------
FENETRE_COMPARAISON = 20_000            # ne comparer que les N premiers caractères
# Similarité de corps (difflib ratio, 0..1) :
SIMILARITE_IDENTIQUE = 0.98            # >= : corps quasi identiques -> statique/public
SIMILARITE_GABARIT_MIN = 0.30         # dans [MIN, IDENTIQUE) : même gabarit, données ≠
MIN_200_STABLE = 3                     # nb min de 200 dans l'échantillon pour « énumérable »

# --- Ajustements de score (la décision vit ici) -------------------------------
BONUS_CANDIDAT_SERIEUX = 4            # 200 stable + contenu diff structuré
MALUS_PROBABLE_PUBLIC = -4           # contenu identique quel que soit l'id

# --- Content-type : garer les ASSETS de présentation comme "public" -----------
# Types de PRÉSENTATION (pas des données possédées) : un endpoint qui rend ça est
# public par nature — inutile de le sonder, des variantes différentes (images) ne
# doivent pas déclencher candidat_serieux par similarité basse.
# NE PAS y mettre application/pdf, application/xml, application/json, text/html,
# application/octet-stream, text/plain : ce sont des DONNÉES potentielles (un PDF/XML
# peut être un document possédé fuité) -> elles continuent vers la similarité (et le
# juge sémantique en étape 2). Set éditable.
ASSET_CONTENT_TYPES = {
    "image/*", "font/*", "audio/*", "video/*",
    "text/css", "application/javascript", "text/javascript",
}
MALUS_ASSET_PUBLIC = -4              # dépriorisation d'un endpoint d'asset (borné à 0, jamais retiré)

# Valeur du lead au-dessus de laquelle on NE fait PAS confiance à l'échantillon
# stocké : on SONDE d'autres ids découverts (per-id) au lieu de court-circuiter sur un
# seul content-type. En dessous, on fait confiance au stocké (asset -> public, 0 req).
SEUIL_SONDE = 3


# --- Sonde AUTH-BYPASS (brique B) : bornes DURES + seuils de décision ----------
# Rejoue un endpoint 401/403 avec des mutations d'accès et compare au baseline. Preuve
# EXÉCUTÉE uniquement : on n'affirme un contournement que sur un 401/403 -> 200 dont le
# CONTENU diffère réellement du refus (un 200 identique au corps de refus = faux positif).
AUTH_STATUTS_CIBLES = {401, 403}       # seuls statuts sur lesquels un bypass a un sens
AUTH_MAX_MUTATIONS_PAR_ENDPOINT = 8   # borne dure : nb de tentatives de bypass / endpoint
AUTH_MAX_ENDPOINTS_PAR_HOST = 12      # borne dure : nb d'endpoints sondés / host / run
# Un 200 obtenu APRÈS mutation ne compte comme bypass que si son corps s'écarte assez du
# corps de refus baseline (sinon c'est la même page de refus renvoyée en 200 -> faux positif).
AUTH_SIMILARITE_MAX_AVEC_REFUS = 0.90  # < : contenu réellement différent -> bypass crédible
BONUS_AUTH_BYPASS = 6                  # repriorisation forte d'un bypass crédible (borné par le board)


# --- Sonde CORS (brique B) : rejoue avec une Origin ATTAQUANTE, mesure le reflet ---------
# Preuve EXÉCUTÉE : on n'affirme un CORS exploitable que si la réponse REFLÈTE notre Origin
# attaquante (ACAO == Origin envoyée, ou '*') ET autorise les credentials — c.-à-d. un
# navigateur tiers lirait la réponse authentifiée. Un ACAO fixe (allowlist) = non exploitable.
CORS_ORIGIN_ATTAQUANT = "https://attacker.example"   # origine hors-cible, non résolue (aucun trafic vers elle)
CORS_MAX_ENDPOINTS_PAR_HOST = 15      # borne dure : nb d'endpoints CORS sondés / host / run
BONUS_CORS_REFLETE = 5                 # repriorisation d'un reflet Origin+creds crédible

# --- Sonde OPEN-REDIRECT (brique B) : mute le param de redirection vers un domaine externe -
# Preuve EXÉCUTÉE : on n'affirme un open redirect que si la Location du premier-hop pointe
# réellement vers le domaine EXTERNE injecté (pas seulement le reflète dans une page).
OPENREDIR_DOMAINE_TEMOIN = "attacker.example"   # domaine témoin (jamais joint : redirection non suivie)
OPENREDIR_MAX_ENDPOINTS_PAR_HOST = 15  # borne dure : nb d'endpoints open-redirect sondés / host / run
OPENREDIR_MAX_PAYLOADS = 4            # nb de variantes d'injection par endpoint
BONUS_OPEN_REDIRECT = 4                # repriorisation d'un open redirect prouvé


def est_content_type_asset(ct):
    """True si le content-type est un type de PRÉSENTATION (asset public).
    Insensible à la casse, ignore le charset (';'), gère les familles image/* etc."""
    ct = (ct or "").split(";")[0].strip().lower()
    if not ct:
        return False
    if ct in ASSET_CONTENT_TYPES:
        return True
    return (ct.split("/")[0] + "/*") in ASSET_CONTENT_TYPES


# --- SSRF (réflexion locale, ROE-safe) --------------------------------------
SSRF_MAX_ENDPOINTS_PAR_HOST = 12
SSRF_ECART_MIN = 0.15
SSRF_ECART_TIMING = 2.0
SSRF_PARAM_BONUS = 7
SSRF_TEMOIN_TMPL = "http://ssrf-canary-nonexistent.{host}/"

# --- SSTI / SQLi / déser (probes high, détection prudente) -------------------
SSTI_MAX_ENDPOINTS_PAR_HOST = 12
SSTI_MARQUEUR = "1337"          # 7*191 = 1337 : produit improbable dans une page normale
SSTI_PAYLOADS = ["{{7*191}}", "${7*191}", "#{7*191}", "<%= 7*191 %>", "*{7*191}"]
SQLI_MAX_ENDPOINTS_PAR_HOST = 12
SQLI_ECART_MIN = 0.15           # écart guillemet-cassant vs échappé => anomalie SQL
DESER_MAX_ENDPOINTS_PAR_HOST = 12
