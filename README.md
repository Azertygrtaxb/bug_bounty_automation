# bug_bounty_automation — squelette d'infrastructure

Le tuyau à vide : Postgres + Redis + un worker Celery. Pas de recon, pas de
scoring, pas d'IA. Juste de quoi vérifier qu'une tâche traverse
Redis → Celery → Postgres.

## Arborescence

```
engine/            # tout le code d'infrastructure
  celery_app.py    # app Celery (broker via env)
  tasks.py         # insert_dummy_target(url)
  enqueue.py       # CLI pour pousser une tâche
  db/001_init.sql  # schéma (targets, jobs) — joué à la création du volume
  Dockerfile       # image du worker (Python 3.12)
  requirements.txt
knowledge/         # connaissance (signaux, listes) — vide pour l'instant
config/            # config par cible — vide pour l'instant
docker-compose.yml # postgres, redis, worker
.env.example       # copier vers .env
```

## Démarrer et vérifier

```bash
cd bug_bounty_automation
cp .env.example .env          # (un .env de dev est déjà fourni)

docker compose up -d --build  # postgres + redis + worker

# 1) pousser une tâche factice depuis l'hôte
pip install python-dotenv celery[redis]   # deps du CLI, si absentes
python engine/enqueue.py insert_dummy_target http://test.local

# 2) vérifier que la ligne est bien en base
docker compose exec postgres \
  psql -U bbhunter -d bugbounty -c "SELECT id, url, host, statut_host, cree_le FROM targets;"
```

La requête doit afficher la ligne `http://test.local` insérée par le worker.
