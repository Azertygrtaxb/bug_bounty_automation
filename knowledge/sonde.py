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
