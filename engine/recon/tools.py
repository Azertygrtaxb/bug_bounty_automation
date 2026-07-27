"""Enveloppes fines autour de subfinder / httpx / katana.

Découverte PASSIVE uniquement : énumération OSINT, probe en lecture (GET/HEAD),
crawl des liens réellement exposés. Aucun brute-force, aucune wordlist.
Débit borné par des limites de requêtes (-rl) sur chaque outil.
"""
import json
import os
import subprocess
import tempfile

from engine.ratelimit import RECON_PROXY

TOOL_TIMEOUT = int(os.environ.get("RECON_TOOL_TIMEOUT", "1200"))  # secondes / outil
# Débit PAR-HOST des binaires recon. Défaut CONSERVATEUR (rester sous le radar WAF) ;
# le cap global vient du nombre de hosts simultanés (slots ratelimit) x ce débit.
RATE_LIMIT = os.environ.get("RECON_RATE_LIMIT", "5")              # requêtes / seconde / host
CRAWL_DEPTH = os.environ.get("RECON_CRAWL_DEPTH", "2")


def _proxy_args():
    """Point d'accroche egress : -proxy si RECON_PROXY est défini (IPs tournantes)."""
    return ["-proxy", RECON_PROXY] if RECON_PROXY else []


def _run(cmd, input_text=None):
    return subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=TOOL_TIMEOUT,
    )


def run_subfinder(host):
    """Sous-domaines via sources passives (OSINT). Inclut toujours le host lui-même."""
    proc = _run(["subfinder", "-d", host, "-silent"])
    subs = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
    subs.add(host)
    return sorted(subs)


def run_httpx(inputs):
    """Probe en lecture les hosts/URLs vivants. Renvoie une liste d'objets JSON httpx
    (url, status_code, tech, title, tls...). GET/HEAD uniquement."""
    if not inputs:
        return []
    cmd = [
        "httpx",
        "-silent", "-json", "-no-color",
        "-status-code", "-title", "-tech-detect", "-tls-grab",
        "-hash", "sha256",       # hash du corps FINAL -> body_hash (catch-all)
        "-follow-redirects",     # suit jusqu'au contenu final (catch-all en depend)
        "-include-response",     # -irr : sort body + header (dict) DEJA en main -> aucun round-trip
        # chain_status_codes + final_url exposent le PREMIER-HOP a cote du final
        "-rate-limit", RATE_LIMIT,
        "-timeout", "10",
    ] + _proxy_args()
    proc = _run(cmd, input_text="\n".join(inputs))
    out = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def run_katana(seed_urls, depth=None, light=False):
    """Crawl les liens exposés depuis les URLs racines. Paramétrable pour la recon
    tiérée :
      - depth : profondeur (défaut = CRAWL_DEPTH ; le shallow passe 0-1) ;
      - light : True (SHALLOW) = robots/sitemap + crawl peu profond SANS le crawl JS
        (jsluice), coûteux ; False (DEEP) = crawl JS complet (-jc -jsluice).
    Restreint au domaine racine (-fs rdn). Aucun fuzzing."""
    if not seed_urls:
        return []
    depth = str(depth if depth is not None else CRAWL_DEPTH)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
        fh.write("\n".join(seed_urls))
        seedfile = fh.name
    try:
        cmd = [
            "katana",
            "-list", seedfile,
            "-depth", depth,
            "-known-files", "all",
            "-field-scope", "rdn",
            "-rate-limit", RATE_LIMIT,
            "-concurrency", "5",
            "-timeout", "10",
            "-silent",
        ]
        if not light:
            cmd += ["-js-crawl", "-jsluice"]   # crawl JS seulement en DEEP (coûteux)
        cmd += _proxy_args()
        proc = _run(cmd)
    finally:
        os.unlink(seedfile)
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
