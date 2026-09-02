"""Tests du CŒUR DÉCISIONNEL sémantique (fonctions PURES, aucun réseau, aucun LLM).

Verrouille l'ASYMÉTRIE voulue :
  - REPÊCHER GÉNÉREUSEMENT : un applicatif/surface_auth remonte le résidu, même par-dessus
    un déterministe faible (rater une cible coûte une vuln).
  - FILTRER TIMIDEMENT : institutionnel ne mord QUE si le déterministe est nul (démoter à
    tort une vitrine ne coûte que du bruit) — jamais devant un signal déterministe.
  - PLAFOND DUR : aucun repêchage LLM ne passe devant un vrai signal déterministe fort.
  - JAMAIS DÉMOTANT sur repêchage : un bonus ne fait pas BAISSER un score déjà élevé.

Lancer : python -m unittest knowledge.test_semantique   (depuis la racine du repo)
"""
import unittest

from knowledge import config, semantique


class TestComposerPriorite(unittest.TestCase):
    # --- REPÊCHAGE applicatif : sort le résidu de l'ombre -----------------------
    def test_applicatif_repeche_le_residu_zero(self):
        prio, raison = semantique.composer_priorite(0, "applicatif")
        self.assertEqual(prio, min(config.BONUS_APPLICATIF, config.PLAFOND_SEM))
        self.assertIsNotNone(raison)
        self.assertIn("applicatif", raison)

    def test_applicatif_peut_depasser_un_deterministe_faible(self):
        # score_det=1 (faible) + bonus 3 -> 4, borné à PLAFOND_SEM. Le repêchage DÉPASSE
        # bien le déterministe faible : c'est le comportement "ne rate pas une cible".
        prio, _ = semantique.composer_priorite(1, "applicatif")
        self.assertEqual(prio, min(1 + config.BONUS_APPLICATIF, config.PLAFOND_SEM))
        self.assertGreater(prio, 1)

    # --- PLAFOND DUR : ne passe jamais devant un déterministe fort --------------
    def test_plafond_borne_le_bonus(self):
        # score_det déjà au plafond -> le bonus n'ajoute RIEN (delta 0 -> pas de raison).
        prio, raison = semantique.composer_priorite(config.PLAFOND_SEM, "applicatif")
        self.assertEqual(prio, config.PLAFOND_SEM)
        self.assertIsNone(raison)

    def test_bonus_jamais_demotant_sur_signal_fort(self):
        # Un déterministe fort (au-dessus du plafond, ex. id +6, fingerprint +8) n'est
        # JAMAIS abaissé par le plafond sémantique : max() protège.
        for fort in (6, 8, 10):
            prio, raison = semantique.composer_priorite(fort, "applicatif")
            self.assertEqual(prio, fort, "le plafond ne doit jamais démoter un signal fort")
            self.assertIsNone(raison)

    def test_surface_auth_repeche_avec_son_bonus(self):
        prio, raison = semantique.composer_priorite(0, "surface_auth")
        self.assertEqual(prio, min(config.BONUS_SURFACE_AUTH, config.PLAFOND_SEM))
        self.assertIn("surface_auth", raison)

    # --- FILTRAGE institutionnel : timide, subordonné au déterministe ----------
    def test_institutionnel_mord_seulement_si_deterministe_nul(self):
        prio, raison = semantique.composer_priorite(0, "institutionnel")
        self.assertEqual(prio, 0 - semantique.PENALITE_INSTITUTIONNEL)
        self.assertIn("institutionnel", raison)

    def test_institutionnel_ignore_si_deterministe_a_un_signal(self):
        # dès score_det >= SIGNAL_DET_PLANCHER, la démotion est IGNORÉE (jamais contredire
        # un signal déterministe). C'est le "filtrer timidement".
        prio, raison = semantique.composer_priorite(semantique.SIGNAL_DET_PLANCHER,
                                                    "institutionnel")
        self.assertEqual(prio, semantique.SIGNAL_DET_PLANCHER)
        self.assertIsNone(raison)

    # --- Verdicts neutres : aucun effet ----------------------------------------
    def test_incertain_et_auth_wall_sont_neutres(self):
        for v in ("incertain", "EXCLU_auth_wall", "inconnu", None):
            prio, raison = semantique.composer_priorite(2, v)
            self.assertEqual(prio, 2)
            self.assertIsNone(raison)


class TestDecider(unittest.TestCase):
    def test_frontiere_auth_route_en_surface_auth(self):
        # Routage prioritaire : une frontière d'auth dans le contenu -> surface_auth,
        # jamais scorée/démotée par le portee=public constant.
        classe, detail = semantique.decider({"frontiere_auth": "présente", "portee": "public"})
        self.assertEqual(classe, "surface_auth")

    def test_par_utilisateur_plus_nudges_applicatif(self):
        classe, detail = semantique.decider({
            "portee": "par_utilisateur", "entrees": "oui", "objet_parametre": "objet",
            "carte_surface": "non", "structure": "fonctionnel",
            "nature_valeurs": "operationnel", "frontiere_auth": "absente",
            "fuite_technique": "non"})
        self.assertEqual(classe, "applicatif")
        self.assertGreaterEqual(detail["net"], semantique.SEUIL)

    def test_public_narratif_descriptif_institutionnel(self):
        classe, detail = semantique.decider({
            "portee": "public", "entrees": "non", "objet_parametre": "aucun",
            "carte_surface": "non", "structure": "narratif",
            "nature_valeurs": "descriptif", "frontiere_auth": "absente",
            "fuite_technique": "non"})
        self.assertEqual(classe, "institutionnel")
        self.assertLessEqual(detail["net"], -semantique.SEUIL)

    def test_proche_du_seuil_incertain(self):
        # public (-2) + un seul nudge applicatif (+1) = -1 -> |net| < SEUIL -> incertain
        classe, detail = semantique.decider({
            "portee": "public", "entrees": "oui", "objet_parametre": "aucun",
            "carte_surface": "non", "structure": "fonctionnel",
            "nature_valeurs": "operationnel", "frontiere_auth": "absente",
            "fuite_technique": "non"})
        self.assertEqual(classe, "incertain")

    def test_valeur_hors_enum_comptee_zero(self):
        # une valeur inconnue ne casse pas et ne contribue pas (robustesse).
        classe, _ = semantique.decider({"portee": "n_importe_quoi"})
        self.assertEqual(classe, "incertain")


if __name__ == "__main__":
    unittest.main()
