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


def est_content_type_asset(ct):
    """True si le content-type est un type de PRÉSENTATION (asset public).
    Insensible à la casse, ignore le charset (';'), gère les familles image/* etc."""
    ct = (ct or "").split(";")[0].strip().lower()
    if not ct:
        return False
    if ct in ASSET_CONTENT_TYPES:
        return True
    return (ct.split("/")[0] + "/*") in ASSET_CONTENT_TYPES
