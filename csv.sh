#!/usr/bin/env bash
cd /home/bug_bounty_automation
OUT="${1:-/root/leads.csv}"
docker compose exec -T postgres psql -U bbhunter -d bugbounty \
 -c "\copy (SELECT host, url, score, http_status, array_to_string(score_raisons,' | ') AS raisons, array_to_string(tech,',') AS tech FROM targets WHERE score>0 ORDER BY score DESC, host) TO STDOUT WITH CSV HEADER" > "$OUT"
echo "→ $OUT ($(wc -l < "$OUT") lignes, dont 1 en-tête)"
