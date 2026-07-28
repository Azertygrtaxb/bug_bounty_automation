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

## Dashboard de chasse (Tier 4)

Le board LIT `leads` et ÉCRIT `leads_statut`. Il ne rescore jamais, ne relance jamais de
recon, ne touche jamais `targets` (sauf lecture). Serveur stdlib (`engine/board.py`),
une page (`engine/board.html`), zéro build front.

```bash
# migrations à jour (006→010) puis :
docker compose up -d board
# board publié sur 127.0.0.1:8080 UNIQUEMENT. Depuis ta machine :
ssh -L 8080:localhost:8080 root@<vps>   # puis http://localhost:8080
```

Accès machine (le collègue) : `GET /api/leads?min_score=6&quota=0` renvoie du JSON pur.

### Exposition
- `BOARD_EXPOSE=0` (défaut) : localhost/tunnel, basic-auth optionnelle. Le **panneau de
  détail** (`/api/lead/detail`, données capturées sensibles) exige TOUJOURS une auth :
  renseigne `BOARD_USER`/`BOARD_PASS` pour l'activer.
- `BOARD_EXPOSE=1` : bind 0.0.0.0 + basic-auth OBLIGATOIRE partout ; refuse de démarrer si
  `BOARD_PASS` est vide. Pense aussi à `BOARD_BIND_HOST=0.0.0.0`. À éviter en HTTP clair
  sur IP publique (identifiants ET cibles exposés) — préfère le tunnel SSH.

### Rôle postgres SELECT-only du board (recommandé)
Le process board n'a besoin que de lire `targets`/`leads` et d'écrire `leads_statut`
(aucun DDL). Crée un rôle dédié (c'est aussi la base du rôle read-only du collègue) :

```sql
CREATE ROLE board_ro LOGIN PASSWORD '...';           -- mets le mot de passe dans .env (BOARD_DB_PASS)
GRANT USAGE ON SCHEMA public TO board_ro;
GRANT SELECT ON targets, leads TO board_ro;          -- lecture seule sur les données calculées
GRANT SELECT, INSERT, UPDATE ON leads_statut TO board_ro;  -- statut de triage humain uniquement
-- (pas de CREATE : le board ne fait aucun DDL ; les migrations tournent avec le compte applicatif)
```
Puis `BOARD_DB_USER=board_ro` + `BOARD_DB_PASS=...` dans `.env`.
