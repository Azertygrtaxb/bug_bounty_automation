"""Tests du ROUTAGE des sondes (fonction pure). Verrouille la CONVERGENCE STRICTE :
une famille n'est planifiée que si sémantique ET déterministe convergent.

Lancer : python -m unittest knowledge.test_routage
"""
import unittest

from knowledge import routage


class TestPlanStrict(unittest.TestCase):
    def setUp(self):
        routage.REGLE_STRICTE = True   # état par défaut, réaffirmé pour l'isolation

    # --- auth_bypass : la famille prouvée de bout en bout -----------------------
    def test_auth_bypass_convergence(self):
        p = routage.plan("surface_auth", ["flux_auth", "fingerprint_produit(+8)"])
        familles = [x["famille"] for x in p]
        self.assertIn("auth_bypass", familles)
        ab = next(x for x in p if x["famille"] == "auth_bypass")
        self.assertTrue(ab["convergence"])
        self.assertIn("flux_auth", ab["declencheur"])

    def test_auth_bypass_verdict_seul_ne_declenche_pas(self):
        # surface_auth SANS aucun token d'auth déterministe -> rien (convergence stricte).
        p = routage.plan("surface_auth", ["fingerprint_produit(+8)"])
        self.assertEqual([x["famille"] for x in p], [])

    def test_auth_bypass_deterministe_seul_ne_declenche_pas(self):
        # flux_auth SANS verdict surface_auth -> rien.
        p = routage.plan("applicatif", ["flux_auth"])
        self.assertNotIn("auth_bypass", [x["famille"] for x in p])

    def test_auth_basic_expose_compte_comme_token_auth(self):
        p = routage.plan("surface_auth", ["auth_basic_exposee"])
        self.assertIn("auth_bypass", [x["famille"] for x in p])

    # --- idor : l'autre famille active -----------------------------------------
    def test_idor_convergence(self):
        p = routage.plan("applicatif", ["id_non_derive_session"])
        self.assertIn("idor", [x["famille"] for x in p])

    def test_idor_api_objet_par_id(self):
        p = routage.plan("applicatif", ["api_objet_par_id"])
        self.assertIn("idor", [x["famille"] for x in p])

    # --- familles définies mais SANS sonde écrite : masquées par défaut ---------
    def test_cors_masque_car_sonde_absente(self):
        # convergence réelle, mais 'cors' n'est pas dans FAMILLES_ACTIVES -> pas planifiée
        # tant que actives_seulement=True (défaut).
        p = routage.plan("applicatif", ["cors_permissif"])
        self.assertNotIn("cors", [x["famille"] for x in p])

    def test_cors_visible_si_actives_seulement_false(self):
        p = routage.plan("applicatif", ["cors_permissif"], actives_seulement=False)
        self.assertIn("cors", [x["famille"] for x in p])

    # --- verdicts neutres : aucun plan -----------------------------------------
    def test_incertain_ne_planifie_rien(self):
        for v in ("incertain", "institutionnel", "EXCLU_auth_wall", None):
            self.assertEqual(routage.plan(v, ["flux_auth", "id_non_derive_session"]), [])

    def test_raisons_vides_ne_plantent_pas(self):
        self.assertEqual(routage.plan("surface_auth", None), [])
        self.assertEqual(routage.plan("surface_auth", []), [])


class TestPlanRelache(unittest.TestCase):
    def tearDown(self):
        routage.REGLE_STRICTE = True   # NE PAS fuiter l'état vers les autres tests

    def test_relache_un_seul_signal_suffit(self):
        routage.REGLE_STRICTE = False
        # verdict seul suffit maintenant
        p = routage.plan("surface_auth", ["fingerprint_produit(+8)"])
        self.assertIn("auth_bypass", [x["famille"] for x in p])
        # déterministe seul aussi
        p2 = routage.plan("applicatif", ["flux_auth"])
        self.assertIn("auth_bypass", [x["famille"] for x in p2])
        # mais la convergence reste tracée à False dans ces cas
        ab = next(x for x in p if x["famille"] == "auth_bypass")
        self.assertFalse(ab["convergence"])


if __name__ == "__main__":
    unittest.main()
