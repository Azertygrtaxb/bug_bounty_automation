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
# migrations à jour (006→011) + BOARD_ACCOUNTS + BOARD_DOMAINE dans .env, puis :
docker compose up -d          # postgres, redis, worker, board, caddy
# -> https://<BOARD_DOMAINE> (Caddy, cert auto, login demandé). Voir « Mise en ligne » plus bas.
```

Accès machine (le collègue) : `GET /api/leads?min_score=6&quota=0` (avec auth, en HTTPS) renvoie du JSON pur.

### Login (obligatoire, board partagé à deux)
Le board porte la carte d'attaque d'un périmètre bancaire : **login obligatoire partout**,
il refuse de démarrer sans compte. Un compte par chasseur, **mot de passe haché** :

```bash
# génère chaque compte (mot de passe saisi sans écho) :
docker compose run --rm board python -m engine.board --hash-pass
# -> imprime 'alice:pbkdf2$600000$…' ; colle les comptes séparés par des virgules :
BOARD_ACCOUNTS='alice:pbkdf2$…,bob:pbkdf2$…'          # dans .env, jamais committé
```

Un mot de passe **en clair** reste accepté (rétro-compat) mais le serveur **avertit** au
démarrage en nommant le compte. On hache non pas contre un VPS compromis (qui a la base a
tout) mais contre la **réutilisation** du mot de passe ailleurs.

- Comparaison **timing-safe** (pbkdf2 + `compare_digest`, anti-énumération).
- **Anti-bruteforce** : au-delà de `BOARD_MAX_ECHECS` (5) échecs par (compte, IP) en
  `BOARD_FENETRE_ECHECS` (300 s) -> `429 Retry-After`, sans comparer le mot de passe.
- **CSRF** : POST exige l'en-tête custom `X-Board` + `Origin` même hôte. **Journal** stderr :
  échecs de login, blocages, et chaque POST (qui/quel lead/quel statut) — jamais le mot de
  passe ni le corps. Chaque statut trace **qui** (`par_qui`, UI + API).
- **En-têtes** sur la page : `Content-Security-Policy` (aucune connexion/image sortante) +
  `X-Frame-Options: DENY`.
- **X-Forwarded-For** n'est cru que si la connexion vient d'un `PROXIES_DE_CONFIANCE` (§14,
  défaut = réseau Docker) ; sinon l'en-tête est ignoré (sinon un client direct ferait tomber
  le blocage anti-bruteforce sur un compte innocent). L'IP retenue est journalisée.
- Exposition : voir **Mise en ligne** (Caddy HTTPS, défaut) ou le mode tunnel de secours.
  Le login reste obligatoire dans tous les cas.

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

### Mise en ligne (HTTPS via Caddy)
Caddy est la **seule** porte d'entrée publique (ports 80 et 443). Le board n'est PAS publié
sur l'hôte : Caddy le joint par le réseau Docker interne (`board:8080`).

1. **DNS** : crée un enregistrement A `board.exemple.com` → IP du VPS. (Dépannage sans DNS :
   `BOARD_DOMAINE=<ip-avec-tirets>.nip.io`, ex. `203-0-113-7.nip.io`.)
2. **.env** : `BOARD_DOMAINE=board.exemple.com`, `BOARD_EXPOSE=1`, `BOARD_ACCOUNTS='…'` hachés.
3. **Pare-feu** : ouvre **80 et 443 UNIQUEMENT** (80 sert le challenge ACME + la redirection).
   22 (SSH) reste pour l'admin. Rien d'autre.
4. `docker compose up -d` → Caddy obtient le certificat, sert `https://board.exemple.com`,
   redirige HTTP→HTTPS et ajoute `Strict-Transport-Security`.

**Couple contre-intuitif** : il faut `BOARD_EXPOSE=1` (l'app écoute sur `0.0.0.0` DANS le
conteneur, sinon Caddy ne l'atteint pas) **ET pourtant aucun port board n'est publié** sur
l'hôte — l'écoute 0.0.0.0 est interne au réseau Docker, l'unique exposition reste Caddy.
`ss -ltnp` sur le VPS ne doit montrer que 80, 443 (et 22).

**Retour au mode tunnel** (sans Caddy, ex. debug) : garde `BOARD_EXPOSE=1` (l'app doit écouter
sur `0.0.0.0` dans le conteneur pour qu'un port publié l'atteigne), décommente la section
`ports:` du service `board` (`127.0.0.1:8080:8080` — publié seulement sur la loopback de
l'hôte), arrête Caddy, puis `ssh -L 8080:localhost:8080 root@<vps>` → http://localhost:8080.
(`BOARD_EXPOSE=0` ne sert qu'au dev local HORS docker : l'app écoute alors 127.0.0.1.)

postgres et redis n'ont **aucun** port publié (réseau Docker interne). Accès DB depuis
l'hôte : `docker compose exec postgres psql -U <user> -d <db>`.

## Juge sémantique (repêchage LLM du résidu)

Un juge LLM **aveugle** relit les corps **déjà stockés** (aucun re-fetch réseau) pour
REPÊCHER le résidu que le déterministe ne voit pas — il ne démote pas. Verdict `applicatif`
→ +3, `surface_auth` → +2, plafonné à `PLAFOND_SEM` (5) : un repêchage ne passe jamais
devant un vrai signal (id +6, fingerprint +8). Raison portée explicite (`semantique_applicatif(+3)`).

- **Clé** : `ANTHROPIC_API_KEY` dans le bloc `environment:` du **service worker** uniquement
  (le worker n'a pas d'`env_file`). **Jamais** dans le service board (exposé). Vide →
  `juger_semantique` refuse avec un message explicite. `.env` est gitignoré.
- **Qui est jugé** : le résidu (score 0..`SEUIL_RESIDU`, vivant, non-asset par URL **et** par
  content-type, non déjà jugé). Un endpoint jugé n'est jamais re-jugé (`semantique_juge_le`).
- **Lot** : API Batches (50% moins cher), réassocié par `custom_id`. Plafond de dépense
  côté code `MAX_APPELS_JUGE_PAR_RUN`.

```bash
# migrations à jour (…→012) ; ANTHROPIC_API_KEY renseignée pour le worker ; puis :
docker compose exec worker python -c "from engine.semantique_run import juger_semantique; print(juger_semantique(limite=300))"
docker compose exec worker python -c "from engine.scoring.score import score_targets, rebuild_leads; score_targets(); rebuild_leads()"
```

## Réglage du débit (rate-limiter)

Les variables sont pilotées par `.env` (interpolées dans le service `worker` de
`docker-compose.yml`). **Piège important** : `RL_GLOBAL_MAX_HOSTS` au-delà de
`CELERY_CONCURRENCY` n'a **aucun effet** — le nombre de hosts crawlés en parallèle est le
**minimum des deux** (un worker Celery = un host à la fois). Pour vraiment monter à 24 hosts
simultanés il faut `CELERY_CONCURRENCY=24` ET `RL_GLOBAL_MAX_HOSTS=24`.

Vérifier ce que le conteneur reçoit réellement :
```bash
docker compose config | grep -E "CELERY_CONCURRENCY|RL_"
```
Surcharge locale temporaire sur le VPS : `docker-compose.override.yml` (gitignoré, à
supprimer une fois le lot déployé).
