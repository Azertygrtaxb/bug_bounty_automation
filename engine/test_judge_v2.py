"""Tests de contrat du Juge V2 : aucun réseau et aucune base réelle."""
import os
import unittest
from unittest import mock

os.environ.setdefault("CELERY_BROKER_URL", "memory://")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost/test")

from engine import judge_v2  # noqa: E402
from engine import judge_v2_eval  # noqa: E402
from engine import leads  # noqa: E402
from engine.scoring import score as scoring  # noqa: E402


class _Cursor:
    def __init__(self, rows=()):
        self.rows = list(rows)
        self.calls = []

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchall(self):
        return list(self.rows)


class JudgeV2ContractTests(unittest.TestCase):
    def test_leads_persistence_adapts_v2_decision_as_json(self):
        ligne = {
            "host": "api.example",
            "pattern": "/login",
            "url_representative": "https://api.example/login",
            "score": 9,
            "raisons": [],
            "nb": 1,
            "http_status": 200,
            "tech": [],
            "in_scope": True,
            "premiere_vue": None,
            "semantique_verdict": None,
            "juge_v2": {"primary_surface": "auth_identity"},
            "juge_v2_juge_le": None,
            "domaine_parent": "example",
        }

        class _PersistCursor:
            def execute(self, *_args, **_kwargs):
                return None

            def executemany(self, _sql, rows):
                self.rows = list(rows)

            def fetchone(self):
                return None

            def fetchall(self):
                return []

        class _Context:
            def __init__(self, value):
                self.value = value

            def __enter__(self):
                return self.value

            def __exit__(self, *_args):
                return False

        cur = _PersistCursor()
        conn = mock.Mock()
        conn.cursor.return_value = _Context(cur)
        with mock.patch.object(leads.psycopg, "connect", return_value=_Context(conn)), \
             mock.patch.object(leads, "_assurer_table"), \
             mock.patch.object(leads, "_reconcilier_ancres"), \
             mock.patch.object(leads, "_marquer_orphelins"):
            self.assertEqual(leads.persister([ligne]), 1)

        self.assertEqual(cur.rows[0]["juge_v2"].obj, ligne["juge_v2"])

    def test_decision_is_closed_and_deduplicated(self):
        decision = judge_v2._normaliser_decision({
            "schema_version": judge_v2.SCHEMA_VERSION,
            "primary_surface": "auth_identity",
            "secondary_surfaces": ["api_admin", "api_admin", "auth_identity"],
            "evidence": ["auth_wall", "auth_wall", "not-a-signal"],
            "confidence": "high",
        })
        self.assertEqual(decision["secondary_surfaces"], ["api_admin"])
        self.assertEqual(decision["evidence"], ["auth_wall"])
        self.assertIsNone(judge_v2._normaliser_decision({"primary_surface": "rce"}))

    def test_selection_starts_from_leads_not_raw_targets(self):
        cur = _Cursor([(
            "api.example", "/v1/users/{id}", 11, 42, "<form></form>",
            {"content_type": "text/html"}, "https://api.example/v1/users/1", None, 200,
        )])
        with mock.patch.object(judge_v2, "_est_asset", return_value=False):
            rows = judge_v2.selectionner(cur, 20, 8)
        self.assertEqual(rows[0]["id"], 42)
        sql, params = cur.calls[0]
        self.assertIn("FROM leads l JOIN targets t", sql)
        self.assertIn("t.juge_v2_juge_le IS NULL", sql)
        self.assertEqual(params, (8, 20))

    def test_auth_wall_is_a_free_positive_surface_not_an_exclusion(self):
        decision = judge_v2._decision_auth_wall()
        self.assertEqual(decision["primary_surface"], "auth_identity")
        self.assertEqual(decision["evidence"], ["auth_wall"])
        self.assertEqual(decision["confidence"], "high")

    def test_v2_rebuild_does_not_rescore_targets(self):
        order = []

        def under_lock(operation):
            order.append("lock")
            try:
                return operation()
            finally:
                order.append("unlock")

        with mock.patch.object(judge_v2, "_sous_verrou", side_effect=under_lock), \
             mock.patch.object(judge_v2, "_executer", return_value={"juges": 2}), \
             mock.patch.object(scoring, "_reconstruire_leads", return_value={"persistes": 2}), \
             mock.patch.object(scoring, "_scorer_targets") as scorer:
            result = judge_v2.juger_surface_v2_puis_rebuild.run()
        self.assertEqual(order, ["lock", "unlock"])
        self.assertEqual(result["rebuild_leads"], {"persistes": 2})
        scorer.assert_not_called()

    def test_calibration_is_explicitly_host_level_and_read_only(self):
        self.assertIn("FROM findings_versions", judge_v2_eval._SQL)
        self.assertIn("FROM bb_hackbot_findings", judge_v2_eval._SQL)
        report = judge_v2_eval.resumer([
            {"surface": "technical_exposure", "confiance": "high",
             "label_historique": "manuel_confirme_ou_rapporte", "leads": 2},
        ])
        self.assertEqual(report["leads_v2"], 2)
        self.assertIn("par host", report["caveat"])


if __name__ == "__main__":
    unittest.main()
