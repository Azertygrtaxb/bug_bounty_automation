"""Tests unitaires des garde-fous mémoire/ordre Celery (aucun réseau, aucune DB).

Lancer depuis la racine : python -m unittest engine.test_celery_safety
"""
import os
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("CELERY_BROKER_URL", "memory://")
os.environ.setdefault("DATABASE_URL", "postgresql://test:test@localhost/test")

from engine import celery_app, semantique_run  # noqa: E402
from engine.scoring import score as scoring  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]


class _Cursor:
    def __init__(self, batches=None, fail_write=False):
        self.batches = list(batches or [])
        self.fail_write = fail_write
        self.fetch_sizes = []
        self.executed = []
        self.written_batch_sizes = []
        self.itersize = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchmany(self, size):
        self.fetch_sizes.append(size)
        return self.batches.pop(0) if self.batches else []

    def executemany(self, sql, params):
        params = list(params)
        self.written_batch_sizes.append(len(params))
        if self.fail_write:
            raise RuntimeError("write failed")


class _ScoreConnection:
    def __init__(self, batches, fail_write=False):
        self.aggregate = _Cursor()
        self.reader = _Cursor(batches)
        self.writer = _Cursor(fail_write=fail_write)
        self.normal_cursor_calls = 0
        self.commits = 0
        self.rollbacks = 0
        self.closes = 0

    def cursor(self, name=None):
        if name is not None:
            return self.reader
        self.normal_cursor_calls += 1
        return self.aggregate if self.normal_cursor_calls == 1 else self.writer

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closes += 1


def _row(tid):
    return (
        tid, "https://example.test/%d" % tid, "example.test", 200,
        [], {}, "hash-%d" % tid, 50, None, None, "body", {}, None,
    )


class TestWorkerLimits(unittest.TestCase):
    def test_safe_defaults_and_invalid_values(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(celery_app._entier_worker("CELERY_CONCURRENCY", 2), 2)
        for invalide in ("0", "-1", "abc"):
            with mock.patch.dict(os.environ, {"X": invalide}, clear=False):
                self.assertEqual(celery_app._entier_worker("X", 2), 2)

    def test_tracked_command_applies_all_limits_without_acks_late(self):
        dockerfile = (ROOT / "engine" / "Dockerfile").read_text()
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertIn("--concurrency=${CELERY_CONCURRENCY:-2}", dockerfile)
        self.assertIn("--prefetch-multiplier=${CELERY_PREFETCH_MULTIPLIER:-1}", dockerfile)
        self.assertIn("--max-tasks-per-child=${CELERY_MAX_TASKS_PER_CHILD:-1}", dockerfile)
        self.assertIn('CELERY_CONCURRENCY: "2"', compose)
        self.assertIn('CELERY_PREFETCH_MULTIPLIER: "1"', compose)
        self.assertIn('CELERY_MAX_TASKS_PER_CHILD: "1"', compose)
        self.assertFalse(celery_app.app.conf.task_acks_late)


class TestSemanticSingleton(unittest.TestCase):
    def test_advisory_lock_result(self):
        cur = mock.Mock()
        cur.fetchone.return_value = (True,)
        self.assertTrue(semantique_run._prendre_verrou_jugement(cur))
        self.assertIn("pg_try_advisory_lock", cur.execute.call_args.args[0])

        cur.fetchone.return_value = (False,)
        self.assertFalse(semantique_run._prendre_verrou_jugement(cur))

    def test_session_lock_connection_spans_the_operation(self):
        cur = mock.MagicMock()
        cur.__enter__.return_value = cur
        cur.fetchone.return_value = (True,)
        conn = mock.MagicMock()
        conn.cursor.return_value = cur
        fermee_pendant_operation = []

        def operation():
            fermee_pendant_operation.append(conn.close.called)
            return {"ok": True}

        with mock.patch.object(semantique_run.psycopg, "connect", return_value=conn):
            resume = semantique_run._sous_verrou_jugement(operation, "occupé")
        self.assertEqual(resume, {"ok": True})
        self.assertEqual(fermee_pendant_operation, [False])
        conn.commit.assert_called_once()
        conn.close.assert_called_once()

    def test_overlap_returns_before_selection_or_api(self):
        cur = mock.MagicMock()
        cur.__enter__.return_value = cur
        cur.fetchone.return_value = (False,)
        conn = mock.MagicMock()
        conn.__enter__.return_value = conn
        conn.cursor.return_value = cur
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test"}, clear=False), \
             mock.patch.object(semantique_run.psycopg, "connect", return_value=conn), \
             mock.patch.object(semantique_run, "selectionner") as selectionner:
            resume = semantique_run.juger_semantique.run()
        self.assertTrue(resume["ignore_chevauchement"])
        selectionner.assert_not_called()

    def test_pipeline_overlap_skips_the_entire_chain(self):
        cur = mock.MagicMock()
        cur.__enter__.return_value = cur
        cur.fetchone.return_value = (False,)
        conn = mock.MagicMock()
        conn.cursor.return_value = cur
        with mock.patch.object(semantique_run.psycopg, "connect", return_value=conn), \
             mock.patch.object(semantique_run, "_executer_jugement") as juger, \
             mock.patch.object(scoring, "_scorer_targets") as scorer, \
             mock.patch.object(scoring, "_reconstruire_leads") as rebuild:
            resume = semantique_run.juger_semantique_puis_score_rebuild.run()
        self.assertTrue(resume["ignore_chevauchement"])
        juger.assert_not_called()
        scorer.assert_not_called()
        rebuild.assert_not_called()
        conn.close.assert_called_once()


class TestScoringMemoryAndTransaction(unittest.TestCase):
    def test_lots_are_bounded(self):
        cur = _Cursor([[1] * 750, [2], []])
        self.assertEqual([len(x) for x in scoring._lots(cur)], [750, 1])
        self.assertEqual(cur.fetch_sizes, [750, 750, 750])

    def test_catchall_is_aggregated_without_fetchall(self):
        cur = _Cursor([[('a.test', 'hash-a', 4)], [('b.test', 'hash-b', 2)], []])
        self.assertEqual(scoring._charger_catchall(cur), {
            'a.test': {'hash-a': 4},
            'b.test': {'hash-b': 2},
        })
        sql, params = cur.executed[0]
        self.assertIn("GROUP BY host, body_hash", sql)
        self.assertIn("sum(n) OVER (PARTITION BY host)", sql)
        self.assertEqual(params[0], scoring.substance.CATCHALL_MIN_BODYLEN)

    def test_scoring_batches_then_commits_once(self):
        conn = _ScoreConnection([[_row(i) for i in range(750)], [_row(751)], []])
        with mock.patch.object(scoring.psycopg, "connect", return_value=conn), \
             mock.patch.object(scoring, "_charger_catchall", return_value={}), \
             mock.patch.object(scoring.signaux, "evaluer", return_value=(1, [])), \
             mock.patch.object(scoring.gate, "is_scannable", return_value=True):
            resume = scoring._scorer_targets()
        self.assertEqual(resume, {"scored": 751})
        self.assertEqual(conn.writer.written_batch_sizes, [750, 1])
        self.assertEqual(conn.commits, 1)
        self.assertEqual(conn.rollbacks, 0)
        self.assertEqual(conn.closes, 1)

    def test_write_failure_rolls_back_all_batches(self):
        conn = _ScoreConnection([[_row(1)], []], fail_write=True)
        with mock.patch.object(scoring.psycopg, "connect", return_value=conn), \
             mock.patch.object(scoring, "_charger_catchall", return_value={}), \
             mock.patch.object(scoring.signaux, "evaluer", return_value=(1, [])), \
             mock.patch.object(scoring.gate, "is_scannable", return_value=True):
            with self.assertRaisesRegex(RuntimeError, "write failed"):
                scoring._scorer_targets()
        self.assertEqual(conn.commits, 0)
        self.assertEqual(conn.rollbacks, 1)
        self.assertEqual(conn.closes, 1)


class TestOrderedRebuild(unittest.TestCase):
    def test_beat_has_exactly_one_full_pipeline_task(self):
        planning = celery_app._planning_semantique(120)
        tasks = [x["task"] for x in planning.values()]
        self.assertEqual(tasks, ["juger_semantique_puis_score_rebuild"])

    def test_full_pipeline_order_is_held_under_one_lock(self):
        ordre = []

        def sous_verrou(operation, note):
            ordre.append("lock")
            try:
                return operation()
            finally:
                ordre.append("unlock")

        def juger(limite, modele):
            ordre.append("juger")
            return {"juges": 1}

        def scorer():
            ordre.append("score_commit")
            return {"scored": 2}

        def rebuild(seuil):
            ordre.append("rebuild")
            return {"persistes": 1}

        with mock.patch.object(semantique_run, "_sous_verrou_jugement",
                               side_effect=sous_verrou), \
             mock.patch.object(semantique_run, "_executer_jugement", side_effect=juger), \
             mock.patch.object(scoring, "_scorer_targets", side_effect=scorer), \
             mock.patch.object(scoring, "_reconstruire_leads", side_effect=rebuild):
            resume = semantique_run.juger_semantique_puis_score_rebuild.run()
        self.assertEqual(ordre, ["lock", "juger", "score_commit", "rebuild", "unlock"])
        self.assertEqual(resume["rebuild_leads"], {"persistes": 1})

    def test_rebuild_runs_only_after_score_returns(self):
        ordre = []

        def scorer():
            ordre.append("score_commit")
            return {"scored": 2}

        def rebuild(seuil):
            ordre.append("rebuild")
            return {"persistes": 1}

        with mock.patch.object(scoring, "_scorer_targets", side_effect=scorer), \
             mock.patch.object(scoring, "_reconstruire_leads", side_effect=rebuild):
            resume = scoring.score_targets_puis_rebuild_leads.run()
        self.assertEqual(ordre, ["score_commit", "rebuild"])
        self.assertEqual(resume["rebuild_leads"], {"persistes": 1})

    def test_rebuild_does_not_run_after_score_failure(self):
        with mock.patch.object(scoring, "_scorer_targets", side_effect=RuntimeError("score")), \
             mock.patch.object(scoring, "_reconstruire_leads") as rebuild:
            with self.assertRaisesRegex(RuntimeError, "score"):
                scoring.score_targets_puis_rebuild_leads.run()
        rebuild.assert_not_called()


if __name__ == "__main__":
    unittest.main()
