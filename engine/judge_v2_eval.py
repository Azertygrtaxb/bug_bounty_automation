"""Lecture de calibration du Juge V2, sans appel LLM et sans modifier la base.

Les findings historiques ne donnent pas une vérité exacte endpoint-par-endpoint. Ce
rapport les emploie donc honnêtement comme un proxy *au niveau host* : il permet de
repérer une distribution absurde (p. ex. tout classer "éditorial" malgré des hosts avec
findings confirmés), jamais de prétendre mesurer une précision de vulnérabilité.
"""
import json
import os
from collections import defaultdict

import psycopg


DATABASE_URL = os.environ["DATABASE_URL"]

_SQL = """
WITH manuel AS (
    SELECT host,
           bool_or(statut IN ('confirme', 'rapporte')) AS positif,
           bool_or(statut = 'faux_positif') AS faux_positif,
           bool_or(statut IN ('a_verifier', 'en_cours', 'a_creuser')) AS en_attente
      FROM findings_versions
     GROUP BY host
), hackbot AS (
    SELECT DISTINCT host FROM bb_hackbot_findings
)
SELECT COALESCE(l.juge_v2->>'primary_surface', 'unknown') AS surface,
       COALESCE(l.juge_v2->>'confidence', 'unknown') AS confiance,
       CASE
           WHEN m.positif THEN 'manuel_confirme_ou_rapporte'
           WHEN m.faux_positif THEN 'manuel_faux_positif'
           WHEN h.host IS NOT NULL THEN 'hackbot_signal'
           WHEN m.en_attente THEN 'manuel_en_attente'
           ELSE 'sans_label_historique'
       END AS label_historique,
       count(*) AS leads
  FROM leads l
  LEFT JOIN manuel m ON m.host = l.host
  LEFT JOIN hackbot h ON h.host = l.host
 WHERE l.juge_v2 IS NOT NULL
 GROUP BY 1, 2, 3
 ORDER BY 1, 2, 3
"""


def collecter(conn):
    with conn.cursor() as cur:
        cur.execute(_SQL)
        return [dict(zip((d.name for d in cur.description), row)) for row in cur.fetchall()]


def resumer(rows):
    par_surface = defaultdict(lambda: defaultdict(int))
    total = 0
    for row in rows:
        n = int(row["leads"])
        total += n
        par_surface[row["surface"]][row["label_historique"]] += n
    return {
        "type": "proxy_de_calibration_par_host",
        "caveat": ("corrélation de surface et de findings par host; ce n'est pas une "
                   "mesure de précision de vulnérabilité"),
        "leads_v2": total,
        "par_surface": {surface: dict(labels) for surface, labels in sorted(par_surface.items())},
    }


def main():
    with psycopg.connect(DATABASE_URL) as conn:
        print(json.dumps(resumer(collecter(conn)), ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
