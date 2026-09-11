"""Application Celery : broker lu depuis l'environnement, aucune valeur en dur."""
import os

from celery import Celery

BROKER_URL = os.environ["CELERY_BROKER_URL"]
# Backend de résultat (redis par défaut = le broker) : permet à l'orchestrateur rush
# de suivre la complétion des tâches (AsyncResult.ready/get).
RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", BROKER_URL)


def _entier_worker(nom, defaut):
    """Lit un réglage worker positif, sans laisser une faute de `.env` désactiver
    silencieusement un garde-fou mémoire."""
    try:
        valeur = int(os.environ.get(nom, str(defaut)))
    except (TypeError, ValueError):
        return defaut
    return valeur if valeur > 0 else defaut


def _planning_semantique(intervalle):
    """Une seule entrée Beat : jugement, commit du score, puis rebuild sous verrou."""
    return {
        "semantique-score-rebuild-continu": {
            "task": "juger_semantique_puis_score_rebuild",
            "schedule": intervalle,
        },
    }


app = Celery(
    "bb_automation",
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
    include=["engine.tasks", "engine.recon.discover", "engine.scoring.score",
             "engine.probe.probe", "engine.semantique_run"],
)
app.conf.update(
    result_expires=3600,
    # Le CLI du conteneur reprend les mêmes variables. Les déclarer aussi ici rend
    # les limites effectives pour tout démarrage alternatif du worker.
    worker_concurrency=_entier_worker("CELERY_CONCURRENCY", 2),
    worker_prefetch_multiplier=_entier_worker("CELERY_PREFETCH_MULTIPLIER", 1),
    worker_max_tasks_per_child=_entier_worker("CELERY_MAX_TASKS_PER_CHILD", 1),
)

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
    # Aucun délai estimé : le juge peut durer des heures. La tâche tient le même verrou de
    # session jusqu'au commit score puis au rebuild ; un tick concurrent saute toute la chaîne.
    app.conf.beat_schedule = _planning_semantique(_intervalle)
