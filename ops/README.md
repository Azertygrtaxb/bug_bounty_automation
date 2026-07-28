# OPS — lancer recon et chasse depuis le board

Le board affichait l'état des leads sans permettre d'agir : chaque lancement passait par
un SSH manuel sur le bon VPS. Ce module ajoute les boutons, l'interrupteur on/off et la
page de statut, sans donner au board le droit d'exécuter quoi que ce soit.

## Comment ça tient debout

```
  navigateur                board (conteneur)         PostgreSQL          runner (hôte)
      │                            │                       │                    │
      │ clic « recon www.bci.nc »  │                       │                    │
      ├───────────────────────────►│ INSERT bb_jobs        │                    │
      │                            ├──────────────────────►│                    │
      │                            │                       │◄───────────────────┤ prend un job
      │                            │                       │   (SKIP LOCKED)    │
      │                            │                       │                    ├─► recon.sh
      │ page /ops, toutes les 5 s  │                       │                    │
      ├───────────────────────────►│ SELECT ───────────────►│◄──────────────────┤ rend compte
```

Le board **n'exécute rien**. Il n'a ni `docker.sock`, ni clé SSH, ni accès à l'hôte : il
écrit une ligne. Le runner de la machine concernée vient la prendre. Un mot de passe du
board qui fuite donne donc le droit de **demander** un scan sur une cible dont le nom
valide un motif strict — pas d'exécuter une commande.

Deux validations indépendantes, volontairement redondantes :

| Où | Fichier | Ce qui est vérifié |
|---|---|---|
| board | `engine/ops.py` | host (motif FQDN), options en liste blanche, entiers bornés |
| runner | `ops/job_runner.sh` | **les mêmes règles, refaites en bash** juste avant de construire l'argv |

Si les deux divergent un jour, c'est la seconde qui protège la machine.

## Tables

| Table | Rôle |
|---|---|
| `bb_jobs` | l'exécution : qui a cliqué, quel PID, coupé ou non, rc |
| `bb_controle` | l'interrupteur on/off, une ligne par phase |
| `bb_runners` | battement de cœur : sans lui, un job attendrait indéfiniment sans qu'on sache pourquoi |

`bb_pipeline_runs` (déjà là) garde le **résultat** : urls trouvées, couverture nuclei,
findings. Les deux ne se remplacent pas — sans `bb_jobs`, on ne saurait jamais qu'une
chasse a été coupée à la main plutôt que terminée toute seule.

## Installation

### 1. Base (une seule fois, sur le VPS de chasse)

Les fichiers de `engine/db/` ne sont joués qu'à la **création** du volume PostgreSQL. Sur
une base déjà en service, il faut appliquer la migration à la main :

```bash
docker exec -i bug_bounty_automation-postgres-1 \
    psql -U bbhunter -d bugbounty -v ON_ERROR_STOP=1 < engine/db/013_ops_jobs.sql
```

Elle est idempotente (`IF NOT EXISTS` partout) : la rejouer ne casse rien.

### 2. Board

```bash
docker compose up -d --build board
curl -sI https://<domaine>/ops    # 401 attendu : le login est obligatoire
```

### 3. Runner, sur chaque VPS

```bash
sudo ./ops/install_runner.sh recon     # VPS de reconnaissance
sudo ./ops/install_runner.sh hunt      # VPS de chasse

/opt/bb-ops/job_runner.sh --phase recon --check     # vérifie base, scripts, compte
systemctl enable --now bb-job-runner@recon
```

Réglages par instance dans `/etc/default/bb-job-runner-<phase>` (créé au premier
passage, jamais écrasé ensuite).

## Ce que font les boutons, exactement

| Bouton | Effet | Ce qu'il ne fait pas |
|---|---|---|
| `recon` / `chasse` sur une ligne de host | met un job en file | ne lance rien tout de suite : le runner le prend au tour suivant (≤ 8 s) |
| interrupteur `recon` / `chasse` **OFF** | plus aucun job n'est **pris** | **n'interrompt pas** ce qui tourne déjà |
| `■ stop` sur un job en cours | SIGTERM au groupe de processus, SIGKILL 15 s après | ne supprime rien : journal et findings déjà écrits sont conservés |
| `⏻ TOUT COUPER` | interrupteurs OFF + file vidée + arrêt demandé sur tout | — |

La distinction entre l'interrupteur et le stop est délibérée. Un « off » qui tuerait
aussi les sessions en cours ferait perdre une chasse de 3 h 50 sur un plafond de 4 h à
cause d'un clic de trop. Couper est donc toujours une action explicite et nominative.

Chaque job tourne dans son **propre groupe de processus** (`setsid`) : `recon.sh` lance
une dizaine d'outils en parallèle, et tuer le seul PID du script laisserait `ffuf` et
`nuclei` continuer à marteler la cible, invisibles depuis le board.

## Diagnostic

```bash
python engine/ops.py                    # interrupteurs, runners, jobs vivants
python engine/ops.py purge-fantomes     # jobs 'en_cours' dont le runner est mort
journalctl -u bb-job-runner@recon -f
tail -f /var/log/bb-ops/<id>.log        # sortie brute d'un job
```

| Symptôme | Cause la plus fréquente |
|---|---|
| job coincé en `en_attente` | runner mort (colonne « dernier signe » en rouge sur `/ops`) ou interrupteur sur OFF |
| bouton `chasse` grisé | pas de recon complète sur le VPS de chasse — `hotes_prets` du runner `hunt` |
| `503 … migration 013 probablement pas jouée` | étape 1 sautée |
| job en `echec` avec « host refusé par le runner » | la cible ne valide pas le motif FQDN (majuscule, underscore, port collé au nom) |

## Ce qui n'est volontairement pas là

- **Pas de lancement par lot depuis le web.** `run_batch.sh` existe en ligne de commande
  et sait borner la concurrence ; un bouton « tout scanner » sur 16 000 hôtes ferait
  bannir l'IP avant qu'on ait le temps de le regretter.
- **Pas de modification des paramètres du pipeline depuis le board** (wordlists,
  profils). Ce sont des fichiers versionnés, pas des réglages d'interface.
