"""Orchestrateur RUSH — recon TIÉRÉE pour rendre 48k traitable.

  TIER 1 (shallow) sur TOUS les hosts  ->  RANK  ->  TIER 2 (deep) sur le TOP borné.

Les deux tiers passent par la concurrence Celery bornée + le rate-limiter central
(admission host/filiale/global). Le deep est plafonné (MAX_DEEP_HOSTS) et traité dans
l'ordre du rang (le meilleur d'abord). Lecture seule côté orchestrateur.

Usage :
    python engine/rush.py host1 host2 ...
    python engine/rush.py --file hosts.txt
"""
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

import psycopg  # noqa: E402
from engine.celery_app import app  # noqa: E402
from engine.recon.discover import MAX_DEEP_HOSTS  # noqa: E402
from knowledge import config  # noqa: E402

DB = os.environ["DATABASE_URL"]


def _hosts_from_argv(argv):
    if argv and argv[0] == "--file":
        return [l.strip() for l in Path(argv[1]).read_text().splitlines() if l.strip()]
    return [a.strip().lower() for a in argv if a.strip()]


def _wait_all(results, label, timeout=2400, poll=5):
    """Attend la complétion (à travers les retries d'admission). Renvoie le temps."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        if all(r.ready() for r in results):
            break
        time.sleep(poll)
    dt = time.time() - t0
    ok = sum(1 for r in results if r.successful())
    print("[%s] %d/%d terminés en %.0fs" % (label, ok, len(results), dt))
    return dt


def _rank(hosts):
    """(live triés par DEEP_RANK desc, dead). Un host attribue ses lignes propres +
    celles de ses sous-domaines (host = H OU host LIKE %.H). deep_rank enrichit le
    score shallow de bonus structurels (SPA/produit/nom/cœur) -> ne droppe plus les
    hosts à haute valeur qui scorent 0 tant qu'on n'a pas creusé."""
    live, dead = [], []
    with psycopg.connect(DB) as c, c.cursor() as cur:
        for h in hosts:
            cur.execute("SELECT score, tech, url FROM targets "
                        "WHERE host = %s OR host LIKE %s", (h, "%." + h))
            rows = cur.fetchall()
            if not rows:
                dead.append({"host": h})
                continue
            sc = max((r[0] or 0) for r in rows)
            tech = sorted({t for r in rows for t in (r[1] or [])})
            paths = [r[2] for r in rows]
            dr, detail = config.deep_rank(sc, tech, h, paths)
            live.append({"host": h, "deep_rank": dr, "detail": detail,
                         "surface": len(rows)})
    live.sort(key=lambda x: (x["deep_rank"], x["surface"]), reverse=True)
    return live, dead


def main(argv):
    hosts = _hosts_from_argv(argv)
    if not hosts:
        print("usage: python engine/rush.py host1 host2 ... | --file hosts.txt")
        return 1
    print("=== RUSH tiéré sur %d hosts | promotion par DEEP_RANK (>0) | MAX_DEEP_HOSTS=%d ==="
          % (len(hosts), MAX_DEEP_HOSTS))

    # --- TIER 1 : SHALLOW sur TOUS ---
    sh = [app.send_task("discover_shallow", args=[h]) for h in hosts]
    t_shallow = _wait_all(sh, "TIER1 shallow")
    app.send_task("score_targets").get(timeout=180)

    live, dead = _rank(hosts)
    print("\n--- KILL tier 1 : %d morts (0 ligne) / %d hosts ---" % (len(dead), len(hosts)))
    for d in dead:
        print("   MORT  %s" % d["host"])
    print("\n--- DEEP_RANK (vivants) = score_shallow + spa + produit + nom + core ---")
    print("   %-55s %5s = %4s +%3s +%3s +%3s +%3s" %
          ("host", "RANG", "sh", "spa", "prod", "nom", "core"))
    for x in live:
        d = x["detail"]
        print("   %-55s %5d = %4d +%3d +%3d +%3d +%3d" %
              (x["host"], d["deep_rank"], d["score_shallow"], d["bonus_spa"],
               d["bonus_produit"], d["bonus_nom"], d["bonus_core"]))

    # --- Promotion DEEP : top MAX par deep_rank>0 (plancher = au moins un signal) ---
    deep = [x["host"] for x in live if x["deep_rank"] > 0][:MAX_DEEP_HOSTS]
    ecartes = [x["host"] for x in live if x["host"] not in deep]
    print("\n--- DEEP sélectionnés (ordre de rang, deep_rank>0, plafond %d) ---" % MAX_DEEP_HOSTS)
    for i, h in enumerate(deep, 1):
        print("   #%d  %s" % (i, h))
    print("   (écartés : deep_rank=0 ou hors plafond : %d)" % len(ecartes))

    # --- TIER 2 : DEEP sur le top, dans l'ordre ---
    dp = [app.send_task("discover_deep", args=[h]) for h in deep]  # enqueue = ordre de rang
    t_deep = _wait_all(dp, "TIER2 deep") if dp else 0.0

    # --- Sonde sur les deep (enregistre le WAF centralement) ---
    pr = [app.send_task("probe_idor_candidates", args=[h]) for h in deep]
    _wait_all(pr, "TIER2 sonde") if pr else None

    print("\n=== MÉTRIQUES BRUTES ===")
    print("hosts totaux        : %d" % len(hosts))
    print("tués au tier 1      : %d (morts)" % len(dead))
    print("vivants rankés      : %d" % len(live))
    print("deep-traités        : %d (plafond %d)" % (len(deep), MAX_DEEP_HOSTS))
    print("temps TIER1 shallow : %.0fs (%.1fs/host)" % (t_shallow, t_shallow / max(1, len(hosts))))
    print("temps TIER2 deep    : %.0fs (%.1fs/host deep)" % (t_deep, t_deep / max(1, len(deep))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
