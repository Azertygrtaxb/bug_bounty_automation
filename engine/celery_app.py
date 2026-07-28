"""Application Celery : broker lu depuis l'environnement, aucune valeur en dur."""
import os

from celery import Celery

BROKER_URL = os.environ["CELERY_BROKER_URL"]
# Backend de résultat (redis par défaut = le broker) : permet à l'orchestrateur rush
# de suivre la complétion des tâches (AsyncResult.ready/get).
RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", BROKER_URL)

app = Celery(
    "bb_automation",
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
    include=["engine.tasks", "engine.recon.discover", "engine.scoring.score",
             "engine.probe.probe", "engine.semantique_run"],
)
app.conf.result_expires = 3600
