"""Application Celery : broker lu depuis l'environnement, aucune valeur en dur."""
import os

from celery import Celery

BROKER_URL = os.environ["CELERY_BROKER_URL"]

app = Celery(
    "bb_automation",
    broker=BROKER_URL,
    include=["engine.tasks", "engine.recon.discover", "engine.scoring.score",
             "engine.probe.probe"],
)
