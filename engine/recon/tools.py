"""Enveloppes fines autour de subfinder / httpx / katana.

Découverte PASSIVE uniquement : énumération OSINT, probe en lecture (GET/HEAD),
crawl des liens réellement exposés. Aucun brute-force, aucune wordlist.
Débit borné par des limites de requêtes (-rl) sur chaque outil.
"""
import json
import os
import subprocess
import tempfile

TOOL_TIMEOUT = int(os.environ.get("RECON_TOOL_TIMEOUT", "1200"))  # secondes / outil
RATE_LIMIT = os.environ.get("RECON_RATE_LIMIT", "30")             # requêtes / seconde
CRAWL_DEPTH = os.environ.get("RECON_CRAWL_DEPTH", "2")


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
        # chain_status_codes + final_url exposent le PREMIER-HOP a cote du final
        "-rate-limit", RATE_LIMIT,
        "-timeout", "10",
    ]
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


def run_katana(seed_urls):
    """Crawl les liens exposés depuis les URLs racines : routes réelles, robots/sitemap
    (-kf all), et endpoints extraits du JavaScript (-jc + -jsl/jsluice).
    Restreint au domaine racine de la cible (-fs rdn). Aucun fuzzing."""
    if not seed_urls:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
        fh.write("\n".join(seed_urls))
        seedfile = fh.name
    try:
        cmd = [
            "katana",
            "-list", seedfile,
            "-depth", CRAWL_DEPTH,
            "-js-crawl", "-jsluice",
            "-known-files", "all",
            "-field-scope", "rdn",
            "-rate-limit", RATE_LIMIT,
            "-concurrency", "5",
            "-timeout", "10",
            "-silent",
        ]
        proc = _run(cmd)
    finally:
        os.unlink(seedfile)
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
