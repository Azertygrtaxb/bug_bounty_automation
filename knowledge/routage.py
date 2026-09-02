"""Brique B — ROUTAGE des sondes ciblées (RÈGLE PURE, éditable, sans réseau ni IA).

À partir du VERDICT sémantique (nature du contenu) ET des score_raisons DÉTERMINISTES
(signaux mécaniques), décide QUELLES familles de sonde comportementale un endpoint mérite.
Ne lance AUCUN test : produit un PLAN (liste de familles + le pourquoi), consommé plus tard
par les tâches probe_* après le DEEP.

PRINCIPE — CONVERGENCE STRICTE (levier "qualité, ne pas gaspiller de requêtes") :
  une famille n'est planifiée que si la SÉMANTIQUE et le DÉTERMINISTE CONVERGENT. Si les
  deux couches fonctionnent bien, une vraie surface déclenche les deux signaux ; un seul
  signal = faux positif de l'un ou angle mort de l'autre -> on ne sonde pas (encore).
  Relâcher plus tard (un seul signal -> priorité basse) = changer REGLE_STRICTE + un test.

Symétrie avec semantique.py : fonction pure, valeurs fermées, décision auditable. Le juge
dit ce que le contenu EST ; le déterministe dit quels signaux MÉCANIQUES sont présents ;
le routage dit quel TEST cela justifie. Ni l'un ni l'autre ne juge l'exploitabilité —
seule la sonde (qui touche la cible) le fait.
"""

REGLE_STRICTE = True   # True = convergence sémantique+déterministe requise (éditable)

# --- Familles de sonde : (verdict sémantique requis, {tokens déterministes acceptés}) -----
# Un token est "présent" si un élément de score_raisons COMMENCE par lui (les raisons
# booléennes sont le nom nu, les graduées sont "nom(+N)" -> le préfixe couvre les deux).
# NB : seule 'auth_bypass' a une SONDE écrite pour l'instant (probe_auth_bypass). Les autres
# familles sont DÉFINIES ici (le plan les produira) mais leur probe_* reste à écrire : elles
# documentent la cible et se câbleront une par une, sur le même moule.
FAMILLES = {
    "auth_bypass":   {"verdict": "surface_auth",
                      "det": {"flux_auth", "auth_basic_exposee"}},
    "idor":          {"verdict": "applicatif",
                      "det": {"id_non_derive_session", "api_objet_par_id"}},
    "cors":          {"verdict": "applicatif",
                      "det": {"cors_permissif"}},
    "open_redirect": {"verdict": "applicatif",
                      "det": {"open_redirect_possible"}},
}

# Familles dont la tâche probe_* existe RÉELLEMENT (les seules qu'on ose planifier pour de
# vrai). Élargir en ajoutant la tâche + le nom. Toutes actives : idor (probe_idor_candidates),
# auth_bypass (probe_auth_bypass), cors (probe_cors), open_redirect (probe_open_redirect).
FAMILLES_ACTIVES = {"idor", "auth_bypass", "cors", "open_redirect"}


def _present(token, raisons):
    """token présent dans score_raisons ? (préfixe : couvre 'flux_auth' et 'nom(+N)')."""
    return any((r or "").startswith(token) for r in (raisons or []))


def plan(verdict_sem, score_raisons, actives_seulement=True):
    """Renvoie la liste des familles de sonde méritées : [{famille, verdict, declencheur}].

    verdict_sem   : sortie de semantique.decider ('applicatif'|'surface_auth'|...).
    score_raisons : liste des raisons déterministes (list[str]) de signaux.evaluer.
    actives_seulement : ne retenir que les familles dont la sonde existe (FAMILLES_ACTIVES).

    Convergence stricte : verdict requis ET au moins un token déterministe présent."""
    out = []
    for famille, regle in FAMILLES.items():
        if actives_seulement and famille not in FAMILLES_ACTIVES:
            continue
        verdict_ok = (verdict_sem == regle["verdict"])
        tokens_presents = sorted(t for t in regle["det"] if _present(t, score_raisons))
        if REGLE_STRICTE:
            declenche = verdict_ok and bool(tokens_presents)
        else:
            declenche = verdict_ok or bool(tokens_presents)
        if declenche:
            out.append({
                "famille": famille,
                "verdict": verdict_sem,
                "declencheur": "%s + %s" % (regle["verdict"],
                                            ",".join(tokens_presents) or "(aucun token)"),
                "convergence": verdict_ok and bool(tokens_presents),
            })
    return out
