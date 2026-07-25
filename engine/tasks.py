"""Tâches Celery. Une fonction = un job."""
import os
from urllib.parse import urlparse
from uuid import uuid4

import psycopg

from engine.celery_app import app

DATABASE_URL = os.environ["DATABASE_URL"]


@app.task(name="insert_dummy_target")
def insert_dummy_target(url):
    """Insère une ligne factice dans targets. Sert à valider le tuyau à vide."""
    host = urlparse(url).hostname or url
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO targets (url, host, hash_dedup) "
                "VALUES (%s, %s, %s) RETURNING id",
                (url, host, uuid4().hex),
            )
            new_id = cur.fetchone()[0]
        conn.commit()
    return {"id": new_id, "url": url, "host": host}
