"""Couche sémantique — RÈGLE DE DÉCISION éditable (prototype, pas de production).

À partir des 8 faits extraits À L'AVEUGLE par un juge isolé (sur le CONTENU seul),
décide la NATURE du contenu. Ne juge PAS l'exploitabilité. Fonction pure, sans réseau
ni IA, sur un dict de valeurs fermées.

ALLÈGEMENT (levier 2) — corrige la STRUCTURE, pas les valeurs pour coller aux réponses :
  Constat prouvé : `portee` = "public" sur tout endpoint non-auth (le corps seul ne
  révèle jamais du par-utilisateur), donc l'ancien `fort_neg` était TOUJOURS vrai, donc
  la "contradiction" se réduisait mécaniquement à "auth présente". Poids mort.
  - `frontiere_auth` SORT des faits forts : présente => TAG DE ROUTAGE `surface_auth`
    (surface d'auth à garder, jamais démotée par le portee=public constant), pas un
    score. Ne fabrique plus de fausse contradiction.
  - `fuite_technique` SORT du scoring : la fuite pertinente n'est pas un signal LLM
    recompté ici (brique mécanique future / lead host-spécifique hors pipeline).
"""

# --- Contributions signées (fait -> valeur). portee reste le seul fait « fort ». ---
POIDS = {
    "portee":          {"par_utilisateur": +2, "public": -2},
    # nudges applicatif (+1)
    "entrees":         {"oui": +1},
    "objet_parametre": {"objet": +1},
    "carte_surface":   {"oui": +1},
    # nudges institutionnel (-1)
    "structure":       {"narratif": -1},
    "nature_valeurs":  {"descriptif": -1},
    # frontiere_auth : ROUTAGE, pas de poids (voir decider).
    # fuite_technique : NON scoré (double compte évité).
}

SEUIL = 2   # |score net| < SEUIL => proche du seuil => incertain (éditable)

# --- Composition avec le score DÉTERMINISTE (câblage de PRIORITÉ) --------------
# PRINCIPE (§0.4, §4) : un signal priorise, seul le gate supprime. La couche
# sémantique produit un JUGEMENT -> elle ne supprime JAMAIS (ni score=0, ni retrait).
#
#   FIX 1 : "institutionnel" DÉPRIORISE (pénalité bornée, récupérable), il ne met
#           jamais score=0 ni ne retire l'endpoint. Une fausse démotion coûte une
#           place dans la file, jamais la cible.
#   FIX 2 : le sémantique est SUBORDONNÉ au déterministe. Dès que le score
#           déterministe (signaux.py) porte un vrai signal (>= plancher), le verdict
#           "institutionnel" est IGNORÉ : le score déterministe est un PLANCHER que
#           le sémantique ne peut pas percer. Le sémantique ne mord donc QUE sur le
#           résidu sans aucun signal déterministe.
#
# NB : les démotions DÉTERMINISTES de signaux.py/substance.py (catch-all, page
# d'erreur, redirection canonique, url malformée -> score=0) sont des FAITS
# mécaniques (§6), pas du jugement : elles ne sont PAS touchées ici.
SIGNAL_DET_PLANCHER = 1        # score déterministe >= ce seuil = vrai signal (éditable)
PENALITE_INSTITUTIONNEL = 3    # dépriorisation BORNÉE (fond de file), récupérable (éditable)


def composer_priorite(score_det, verdict_sem):
    """Compose le score DÉTERMINISTE (plancher) avec le VERDICT sémantique.
    Renvoie (priorite, note). Ne met JAMAIS l'endpoint à 0 par jugement, ne le
    retire jamais : au pire un fond de file borné et récupérable.

    score_det : score final de signaux.evaluer() (démotions mécaniques déjà appliquées).
    verdict_sem : 'institutionnel' | 'applicatif' | 'surface_auth' | 'incertain' |
                  'EXCLU_auth_wall' (ce dernier n'est pas un verdict de contenu :
                  l'endpoint n'a pas été jugé, on renvoie le score déterministe tel quel)."""
    if verdict_sem != "institutionnel":
        # applicatif / surface_auth / incertain / exclu : le sémantique ne démote pas.
        return score_det, "sémantique ne mord pas (%s)" % verdict_sem
    if score_det >= SIGNAL_DET_PLANCHER:
        return score_det, ("institutionnel IGNORÉ — signal déterministe %d >= plancher %d"
                           % (score_det, SIGNAL_DET_PLANCHER))
    # aucun signal déterministe : dépriorisation bornée, récupérable, JAMAIS retiré.
    return (score_det - PENALITE_INSTITUTIONNEL,
            "institutionnel -> déprioritisé (-%d), reste en file, récupérable"
            % PENALITE_INSTITUTIONNEL)


def decider(faits):
    """faits: dict des valeurs fermées. Renvoie (classe, detail).

    Routage d'abord : une frontière d'auth dans le CONTENU => surface d'auth (gardée).
    Sinon somme pondérée simple -> applicatif / institutionnel / incertain."""
    if faits.get("frontiere_auth") == "présente":
        return "surface_auth", {"net": None, "contribs": {},
                                "declencheur": "frontiere_auth=présente (routage, non scoré)"}

    contribs = {}
    net = 0
    for fait, table in POIDS.items():
        val = faits.get(fait)
        w = table.get(val, 0)
        contribs[fait] = {"valeur": val, "contribution": w}
        net += w

    if net >= SEUIL:
        classe, declencheur = "applicatif", "net >= +%d" % SEUIL
    elif net <= -SEUIL:
        classe, declencheur = "institutionnel", "net <= -%d" % SEUIL
    else:
        classe, declencheur = "incertain", "proche du seuil (|net| < %d)" % SEUIL

    return classe, {"contribs": contribs, "net": net, "declencheur": declencheur}
