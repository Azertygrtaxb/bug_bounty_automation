"""Tâche Celery de découverte passive d'un host -> table targets.

Chaîne : subfinder (sous-domaines) -> httpx (hosts vivants) -> katana (routes +
JS + robots/sitemap) -> httpx (métadonnées par URL) -> écriture dédupliquée.
"""
import os
from urllib.parse import urlsplit

import psycopg
from psycopg.types.json import Json

from engine.celery_app import app
from engine.recon import tools
from engine.recon.normalize import compute_tags, dedup_key, normalize_url, url_hash

DATABASE_URL = os.environ["DATABASE_URL"]

_TLS_FIELDS = ("host", "tls_version", "cipher", "subject_cn", "issuer_cn", "not_after")


def _tls_summary(tls):
    if not isinstance(tls, dict):
        return None
    summary = {k: tls.get(k) for k in _TLS_FIELDS if tls.get(k)}
    return summary or None


def _body_hash(obj):
    h = obj.get("hash")
    if isinstance(h, dict):
        return h.get("body_sha256")
    return h if isinstance(h, str) else None


def _first_hop(obj):
    """Renvoie (statut_premier_hop, url_destination) À CÔTÉ du contenu final.
    chain_status_codes = [301, 200] quand httpx a suivi une redirection : le
    premier élément est le statut du premier-hop, final_url la destination."""
    chain = obj.get("chain_status_codes") or []
    if chain:
        return chain[0], obj.get("final_url") or None
    return obj.get("status_code"), None  # pas de redirection


def _row_from_httpx(obj):
    """Transforme un objet JSON httpx en ligne targets, ou None si inexploitable."""
    raw = obj.get("url")
    norm = normalize_url(raw)
    if not norm:
        return None
    extra = {
        "title": obj.get("title"),
        "tls": _tls_summary(obj.get("tls")),
        "source": "httpx",
    }
    fh_status, fh_location = _first_hop(obj)
    return {
        "url": norm,
        "host": urlsplit(norm).hostname,
        "http_status": obj.get("status_code"),   # statut FINAL (inchangé)
        "tech": obj.get("tech") or obj.get("technologies") or [],
        "tags": compute_tags(norm, extra),
        "hash": url_hash(dedup_key(raw)),
        "body_hash": _body_hash(obj),             # hash du contenu FINAL (inchangé)
        "body_len": obj.get("content_length"),
        "first_hop_status": fh_status,
        "first_hop_location": fh_location,
    }


def _insert(rows):
    """Insère les lignes, ignore les doublons via hash_dedup. Renvoie (inséré, ignoré)."""
    if not rows:
        return 0, 0
    inserted = 0
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            for r in rows:
                cur.execute(
                    """
                    INSERT INTO targets (url, host, http_status, tech, tags, hash_dedup,
                                         body_hash, body_len, first_hop_status,
                                         first_hop_location)
                    VALUES (%s, %s, %s, %s::text[], %s::jsonb, %s, %s, %s, %s, %s)
                    ON CONFLICT (hash_dedup) DO NOTHING
                    """,
                    (r["url"], r["host"], r["http_status"], r["tech"], Json(r["tags"]),
                     r["hash"], r["body_hash"], r["body_len"],
                     r["first_hop_status"], r["first_hop_location"]),
                )
                inserted += cur.rowcount
        conn.commit()
    return inserted, len(rows) - inserted


@app.task(name="discover_host")
def discover_host(host):
    """Peuple targets à partir d'un seul host, par découverte passive."""
    host = host.strip().lower()

    subdomains = tools.run_subfinder(host)
    live = tools.run_httpx(subdomains)
    root_urls = [o["url"] for o in live if o.get("url")]

    crawled = tools.run_katana(root_urls)

    # Passe de métadonnées : un objet httpx par URL réellement joignable.
    probe_inputs = list(dict.fromkeys(root_urls + crawled))
    probed = tools.run_httpx(probe_inputs)

    rows = {}
    for obj in probed:
        row = _row_from_httpx(obj)
        if row:
            rows[row["hash"]] = row  # dédup en mémoire avant l'insertion

    inserted, skipped = _insert(list(rows.values()))
    return {
        "host": host,
        "subdomains": len(subdomains),
        "live_hosts": len(live),
        "crawled_urls": len(crawled),
        "endpoints": len(rows),
        "inserted": inserted,
        "skipped_duplicates": skipped,
    }
