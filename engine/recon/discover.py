"""Tâche Celery de découverte passive d'un host -> table targets.

Chaîne : subfinder (sous-domaines) -> httpx (hosts vivants) -> katana (routes +
JS + robots/sitemap) -> httpx (métadonnées par URL) -> écriture dédupliquée.
"""
import os
import re
from urllib.parse import urlsplit

import psycopg
from psycopg.types.json import Json

from engine import ratelimit
from engine.celery_app import app
from engine.recon import tools
from engine.recon.normalize import compute_tags, dedup_key, normalize_url, url_hash
from knowledge.signaux import ASSET_EXTENSIONS

DATABASE_URL = os.environ["DATABASE_URL"]
RL_RETRY_COUNTDOWN = int(os.environ.get("RL_RETRY_COUNTDOWN", "20"))  # s entre retentatives d'admission

# --- Recon TIÉRÉE (config éditable) -------------------------------------------
# TIER 1 shallow : profondeur de crawl faible (0-1), pas de crawl JS -> rapide sur
# TOUS les hosts, tue les morts en secondes, produit un score de premier ordre.
SHALLOW_CRAWL_DEPTH = int(os.environ.get("SHALLOW_CRAWL_DEPTH", "1"))
# TIER 2 deep : seuil de promotion (score shallow >= N OU surface > M URLs) et
# plafond de hosts deep-traités par fenêtre.
SEUIL_DEEP = int(os.environ.get("SEUIL_DEEP", "5"))
SEUIL_DEEP_SURFACE = int(os.environ.get("SEUIL_DEEP_SURFACE", "20"))
MAX_DEEP_HOSTS = int(os.environ.get("MAX_DEEP_HOSTS", "10"))

# Corps stocké BORNÉ (caractères), même esprit que body_hash : on garde le contenu
# FINAL pour la couche sémantique, sans stocker des corps géants. Éditable.
CORPS_MAX_STOCKE = 40_000
_ASSET_EXT_RE = re.compile(
    r"\.(" + "|".join(sorted(ASSET_EXTENSIONS)) + r")(?:$|[?#])", re.IGNORECASE)

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


def _is_asset_url(url):
    return bool(_ASSET_EXT_RE.search(urlsplit(url or "").path))


def _body_text(obj, url):
    """Corps FINAL borné à CORPS_MAX_STOCKE. NON stocké pour les assets (.js/.css...)
    : inutile pour la couche sémantique."""
    if _is_asset_url(url):
        return None
    body = obj.get("body")
    if not isinstance(body, str):
        return None
    # PostgreSQL TEXT/JSONB refusent l'octet NUL (0x00) : on le retire.
    return body[:CORPS_MAX_STOCKE].replace("\x00", "")


def _response_headers(obj):
    """En-têtes de réponse (dict httpx 'header' : set_cookie, cors, server,
    www_authenticate, headers de sécurité...). On CAPTURE, aucun signal dessus ici."""
    h = obj.get("header")
    if not isinstance(h, dict) or not h:
        return None
    # Idem : purge les NUL des valeurs (JSONB les refuse aussi).
    return {k: (v.replace("\x00", "") if isinstance(v, str) else v) for k, v in h.items()}


def _first_hop(obj):
    """Renvoie (statut_premier_hop, url_destination) À CÔTÉ du contenu final.
    chain_status_codes = [301, 200] quand httpx a suivi une redirection : le
    premier élément est le statut du premier-hop, final_url la destination."""
    chain = obj.get("chain_status_codes") or []
    if chain:
        return chain[0], obj.get("final_url") or None
    return obj.get("status_code"), None  # pas de redirection


def _row_from_httpx(obj, tier="deep"):
    """Transforme un objet JSON httpx en ligne targets, ou None si inexploitable.
    `tier` (shallow|deep) est tracé dans les tags pour savoir d'où vient la ligne."""
    raw = obj.get("url")
    norm = normalize_url(raw)
    if not norm:
        return None
    extra = {
        "title": obj.get("title"),
        "tls": _tls_summary(obj.get("tls")),
        "source": "httpx",
        "tier": tier,
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
        "body_text": _body_text(obj, norm),       # corps FINAL borné (None pour assets)
        "response_headers": _response_headers(obj),
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
                                         body_hash, body_len, body_text, response_headers,
                                         first_hop_status, first_hop_location)
                    VALUES (%s, %s, %s, %s::text[], %s::jsonb, %s, %s, %s, %s, %s::jsonb, %s, %s)
                    ON CONFLICT (hash_dedup) DO NOTHING
                    """,
                    (r["url"], r["host"], r["http_status"], r["tech"], Json(r["tags"]),
                     r["hash"], r["body_hash"], r["body_len"], r["body_text"],
                     Json(r["response_headers"]) if r["response_headers"] else None,
                     r["first_hop_status"], r["first_hop_location"]),
                )
                inserted += cur.rowcount
        conn.commit()
    return inserted, len(rows) - inserted


def _recon_pipeline(host, shallow):
    """Corps recon commun aux deux tiers. shallow=True : crawl peu profond sans JS
    (rapide, tue les morts en secondes) ; shallow=False : crawl profond + JS (deep).
    Un host non vivant n'insère rien (0 ligne = mort, tué au tier 1)."""
    tier = "shallow" if shallow else "deep"
    subdomains = tools.run_subfinder(host)
    live = tools.run_httpx(subdomains)          # liveness + tech + title + statut
    root_urls = [o["url"] for o in live if o.get("url")]
    if not root_urls:                            # MORT : on s'arrête à la frontière
        return {"host": host, "filiale": ratelimit.filiale_of(host), "tier": tier,
                "live_hosts": 0, "crawled_urls": 0, "endpoints": 0,
                "inserted": 0, "skipped_duplicates": 0}

    if shallow:
        crawled = tools.run_katana(root_urls, depth=SHALLOW_CRAWL_DEPTH, light=True)
    else:
        crawled = tools.run_katana(root_urls, light=False)   # profondeur CRAWL_DEPTH + JS

    probe_inputs = list(dict.fromkeys(root_urls + crawled))
    probed = tools.run_httpx(probe_inputs)       # passe métadonnées (corps + headers)

    rows = {}
    for obj in probed:
        row = _row_from_httpx(obj, tier)
        if row:
            rows[row["hash"]] = row              # dédup en mémoire avant insertion
    inserted, skipped = _insert(list(rows.values()))
    return {"host": host, "filiale": ratelimit.filiale_of(host), "tier": tier,
            "live_hosts": len(live), "crawled_urls": len(crawled),
            "endpoints": len(rows), "inserted": inserted, "skipped_duplicates": skipped}


def _admettre_ou_retenter(task, host):
    """Admission centrale (verrou host + slots filiale/global). Si un cran manque ->
    RETRY (worker libéré, task remise en file)."""
    ok, raison = ratelimit.acquire_host_pour_recon(host)
    if not ok:
        raise task.retry(countdown=RL_RETRY_COUNTDOWN,
                         exc=RuntimeError("admission refusee: " + raison))


@app.task(name="discover_shallow", bind=True, max_retries=100)
def discover_shallow(self, host):
    """TIER 1 — SHALLOW sur TOUS les hosts : rapide, tue les morts, score de rang."""
    host = host.strip().lower()
    _admettre_ou_retenter(self, host)
    try:
        return _recon_pipeline(host, shallow=True)
    finally:
        ratelimit.liberer_host(host)


@app.task(name="discover_deep", bind=True, max_retries=100)
def discover_deep(self, host):
    """TIER 2 — DEEP, seulement sur le TOP prometteur (crawl profond + JS)."""
    host = host.strip().lower()
    _admettre_ou_retenter(self, host)
    try:
        return _recon_pipeline(host, shallow=False)
    finally:
        ratelimit.liberer_host(host)


@app.task(name="discover_host", bind=True, max_retries=100)
def discover_host(self, host):
    """Legacy : découverte complète (= deep) en une passe, admission centrale."""
    host = host.strip().lower()
    _admettre_ou_retenter(self, host)
    try:
        return _recon_pipeline(host, shallow=False)
    finally:
        ratelimit.liberer_host(host)
