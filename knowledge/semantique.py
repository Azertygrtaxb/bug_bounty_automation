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

SEUIL = 1   # |score net| < SEUIL => proche du seuil => incertain (éditable). Baissé 2->1 sur
            # directive : à 2, trop de contenus tombaient en 'incertain' (aucun effet) -> peu de
            # verdicts tranchés. À 1, un seul nudge net suffit à trancher applicatif/institutionnel.

# --- Composition avec le score DÉTERMINISTE (câblage de PRIORITÉ) --------------
# S0 — INVERSION : le sémantique REPÊCHE, il ne démote pas. La vue leads ne garde que
# score >= 1 ; l'ancienne fonction ne poussait que du 0 vers du négatif -> zéro effet sur
# le board. Désormais :
#   'applicatif'     -> + BONUS_APPLICATIF     (sort le candidat de l'ombre)
#   'surface_auth'   -> + BONUS_SURFACE_AUTH   (+ tag de routage côté task)
#   'institutionnel' -> dépriorisation bornée conservée (mord seulement si aucun signal det)
#   'incertain' / 'EXCLU_auth_wall' -> aucun effet
# GARDE-FOU DUR : le score après bonus est PLAFONNÉ à PLAFOND_SEM (§14). Un repêchage LLM
# ne doit JAMAIS passer devant un signal déterministe fort (id +6, fingerprint +8, CORS…).
# Le plafond ne DÉMOTE jamais un score_det déjà supérieur (max()). La raison portée est
# explicite (`semantique_applicatif(+3)`) pour distinguer dans le board le LLM du code.
#
# NB : les démotions DÉTERMINISTES (catch-all, page d'erreur, redirection, url malformée
# -> 0) sont des FAITS mécaniques (§6), pas du jugement : NON touchées ici.
SIGNAL_DET_PLANCHER = 1        # score déterministe >= ce seuil = vrai signal (éditable)
PENALITE_INSTITUTIONNEL = 3    # dépriorisation BORNÉE (fond de file), récupérable (éditable)


def _repecher(score_det, bonus, nom):
    """Bonus borné par PLAFOND_SEM, jamais démotant. Renvoie (priorite, raison|None)."""
    from knowledge import config
    priorite = max(score_det, min(score_det + bonus, config.PLAFOND_SEM))
    delta = priorite - score_det
    if delta <= 0:
        return score_det, None
    return priorite, "semantique_%s(+%d)" % (nom, delta)


def composer_priorite(score_det, verdict_sem):
    """Compose le score DÉTERMINISTE avec le VERDICT sémantique. Renvoie (priorite, raison).
    `raison` = token à ajouter aux score_raisons (None si aucun changement).

    verdict_sem : 'applicatif' | 'surface_auth' | 'institutionnel' | 'incertain' |
                  'EXCLU_auth_wall'."""
    from knowledge import config
    if verdict_sem == "applicatif":
        return _repecher(score_det, config.BONUS_APPLICATIF, "applicatif")
    if verdict_sem == "surface_auth":
        return _repecher(score_det, config.BONUS_SURFACE_AUTH, "surface_auth")
    if verdict_sem == "institutionnel":
        if score_det >= SIGNAL_DET_PLANCHER:
            return score_det, None     # subordonné au déterministe : ignoré
        return (score_det - PENALITE_INSTITUTIONNEL,
                "semantique_institutionnel(-%d)" % PENALITE_INSTITUTIONNEL)
    # incertain / EXCLU_auth_wall / inconnu : aucun effet
    return score_det, None


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
