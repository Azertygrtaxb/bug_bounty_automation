"""Affiche la file de chasse : endpoints scannables triés par score décroissant.

Lecture seule sur la base, lancé depuis l'hôte.
    python engine/queue_view.py [limite]   (limite par défaut : 40)
"""
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
import psycopg

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
DATABASE_URL = os.environ["DATABASE_URL"]

QUERY = """
SELECT score,
       http_status,
       COALESCE(array_to_string(score_raisons, ', '), '') AS raisons,
       url
FROM targets
WHERE COALESCE(tags->>'scannable', 'true') = 'true'
ORDER BY score DESC, id ASC
LIMIT %s
"""


def main(argv):
    limit = int(argv[0]) if argv else 40
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(QUERY, (limit,))
            rows = cur.fetchall()

    if not rows:
        print("(file vide — as-tu lancé la tâche score_targets ?)")
        return 0

    print(f"{'score':>5}  {'stat':>4}  {'raisons':<45}  url")
    print("-" * 110)
    for score, status, raisons, url in rows:
        print(f"{score:>5}  {str(status or '-'):>4}  {raisons:<45.45}  {url}")
    print(f"\n{len(rows)} endpoints (triés par score décroissant).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
