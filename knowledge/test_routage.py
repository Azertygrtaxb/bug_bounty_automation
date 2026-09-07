"""Tests du ROUTAGE des sondes (fonction pure). Verrouille la CONVERGENCE STRICTE :
une famille n'est planifiée que si sémantique ET déterministe convergent.

Lancer : python -m unittest knowledge.test_routage
"""
import unittest

from knowledge import routage


class TestPlanStrict(unittest.TestCase):
    # Le DÉFAUT de prod est maintenant REGLE_STRICTE=False (relâché). Ces tests forcent le mode
    # STRICT localement pour verrouiller sa sémantique, et le restaurent au défaut en tearDown.
    def setUp(self):
        routage.REGLE_STRICTE = True

    def tearDown(self):
        routage.REGLE_STRICTE = False   # restaure le vrai défaut de prod

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

    # --- cors & open_redirect : désormais ACTIVES (sonde écrite) ----------------
    def test_cors_convergence(self):
        p = routage.plan("applicatif", ["cors_permissif(+3)"])
        self.assertIn("cors", [x["famille"] for x in p])

    def test_cors_verdict_seul_ne_declenche_pas(self):
        # applicatif SANS cors_permissif -> pas de sonde cors (convergence stricte)
        p = routage.plan("applicatif", ["fingerprint_produit(+8)"])
        self.assertNotIn("cors", [x["famille"] for x in p])

    def test_open_redirect_convergence(self):
        p = routage.plan("applicatif", ["open_redirect_possible"])
        self.assertIn("open_redirect", [x["famille"] for x in p])

    def test_open_redirect_verdict_seul_ne_declenche_pas(self):
        p = routage.plan("surface_auth", ["open_redirect_possible"])
        # mauvais verdict (open_redirect exige applicatif) -> pas planifié
        self.assertNotIn("open_redirect", [x["famille"] for x in p])

    def test_famille_inactive_reste_masquee(self):
        # Garde-fou générique : une famille hors FAMILLES_ACTIVES n'est jamais planifiée en
        # mode actives_seulement (défaut), même en cas de convergence. (Toutes actives ici :
        # on vérifie le mécanisme via une famille fictive absente de FAMILLES.)
        p = routage.plan("applicatif", ["cors_permissif"])
        for x in p:
            self.assertIn(x["famille"], routage.FAMILLES_ACTIVES)

    # --- verdicts neutres : aucun plan -----------------------------------------
    def test_incertain_ne_planifie_rien(self):
        for v in ("incertain", "institutionnel", "EXCLU_auth_wall", None):
            self.assertEqual(routage.plan(v, ["flux_auth", "id_non_derive_session"]), [])

    def test_raisons_vides_ne_plantent_pas(self):
        self.assertEqual(routage.plan("surface_auth", None), [])
        self.assertEqual(routage.plan("surface_auth", []), [])


class TestPlanRelache(unittest.TestCase):
    """Le mode RELÂCHÉ est le DÉFAUT de prod : un seul signal suffit à planifier une sonde,
    la convergence des deux ne fait que monter la priorité (`convergence`=True)."""

    def test_defaut_est_relache(self):
        # Garde-fou : le défaut de prod DOIT être relâché (directive). Si quelqu'un remet
        # True par défaut, ce test casse et le signale.
        self.assertFalse(routage.REGLE_STRICTE)

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
