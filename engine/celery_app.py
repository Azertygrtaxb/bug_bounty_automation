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

# --- Juge sémantique EN CONTINU (Celery Beat) ------------------------------------------
# Le juge tourne périodiquement sur le résidu non encore jugé et alimente le dashboard V2
# au fil de l'eau, sans déclenchement manuel. Il appelle le LLM (coût réel) : le rythme est
# donc le levier de dépense, réglable par env sans rebuild.
#   SEM_BEAT_ACTIF=1        active la planification (0 = désactivé, défaut off pour ne rien
#                           facturer par accident sur un déploiement qui ne le veut pas)
#   SEM_BEAT_INTERVALLE_S   secondes entre deux runs (défaut 7200 = 2h)
# juger_semantique s'auto-borne : ECHANTILLON_SEM (300) + MAX_APPELS_JUGE_PAR_RUN (300), et
# ne juge que le résidu NON déjà jugé -> quand le résidu est vide, un tour ne coûte rien.
if os.environ.get("SEM_BEAT_ACTIF", "0") == "1":
    _intervalle = float(os.environ.get("SEM_BEAT_INTERVALLE_S", "7200"))
    # Décalage du re-score/rebuild APRÈS le juge : le batch LLM peut durer plusieurs minutes.
    # On lance la propagation sur le MÊME intervalle mais décalée, pour que les verdicts du
    # tour précédent soient déjà persistés quand score_targets/rebuild_leads tournent.
    #   juger    à t = k·intervalle
    #   propager à t = k·intervalle + SEM_BEAT_PROPAGE_DECALAGE_S (défaut 900s = 15 min)
    _decalage = float(os.environ.get("SEM_BEAT_PROPAGE_DECALAGE_S", "900"))
    app.conf.beat_schedule = {
        "juge-semantique-continu": {
            "task": "juger_semantique",
            "schedule": _intervalle,
        },
        # score_targets : lit semantique_verdict -> composer_priorite (repêchage) + remplit
        # sonde_plan (routage). rebuild_leads : propage vers la table `leads` (dashboard).
        "sem-rescore-continu": {
            "task": "score_targets",
            "schedule": _intervalle,
            "options": {"countdown": _decalage},
        },
        "sem-rebuild-leads-continu": {
            "task": "rebuild_leads",
            "schedule": _intervalle,
            "options": {"countdown": _decalage + 120},  # après le re-score
        },
    }
