#!/usr/bin/env bash
set -euo pipefail
cd /home/bug_bounty_automation
PGUSER=bbhunter; PGDB=bugbounty

echo "== 0. Sauvegarde base"
docker compose exec -T postgres pg_dump -U "$PGUSER" "$PGDB" | gzip > "/root/bugbounty-$(date +%F-%H%M).sql.gz"

echo "== 1. Code"
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "ARRÊT : modifications locales non commitées —"; git status --short; exit 1
fi
git pull
git log --oneline -1

echo "== 2. Migrations (idempotentes)"
for f in engine/db/*.sql; do
  echo "   $f"
  docker compose exec -T postgres psql -q -v ON_ERROR_STOP=1 -U "$PGUSER" -d "$PGDB" < "$f"
done

echo "== 3. Rebuild (le code est copié dans l'image)"
docker compose up -d --build worker board

echo "== 4. Vérifications"
docker compose ps
docker compose logs --tail 10 board

if [ "${1:-}" = "--score" ]; then
  echo "== 5. Re-score + reconstruction de la vue"
  docker compose exec -T worker python engine/enqueue.py score_targets
  echo "   (attente de la fin du scoring)"
  until docker compose logs --tail 200 worker | grep -q "'scored'"; do sleep 5; done
  docker compose exec -T worker python engine/leads.py 1 --rebuild
fi
echo "== OK"
