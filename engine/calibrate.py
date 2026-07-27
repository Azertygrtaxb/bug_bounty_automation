"""CALIBRATION de concurrence — trouver le plafond WAF SÛR pour le rush.

PROTOCOLE de mesure (pas une capacité) : monte RL_GLOBAL_MAX_HOSTS par paliers, chaque
palier sur un lot de hosts RICHES en deep-crawl (phase à volume), lit les signaux de
plafond, et S'ARRÊTE au premier signal DÉBIT. Le plafond = dernier palier propre ;
rush recommandé à ~80 %.

⚠️ STEP 0 — PRÉREQUIS DUR : la rotation proxy (RECON_PROXY) doit être BRANCHÉE. Ce
protocole pousse DÉLIBÉRÉMENT jusqu'à faire réagir le WAF ; sans rotation d'IP, on
brûle l'IP de recon avant le rush. Le harnais REFUSE d'escalader si RECON_PROXY est
vide (sauf --force-sans-proxy, à tes risques, paliers très prudents).

RL_FILIALE_MAX_HOSTS reste = 1 (jamais 2 hosts d'une même infra). Il faut donc assez
de FILIALES DISTINCTES dans le lot pour atteindre les hauts paliers.

Usage :
    python engine/calibrate.py --file hosts_riches.txt
    python engine/calibrate.py --paliers 8,16,32,64 --par-palier 24 --file hosts.txt
"""
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from engine import ratelimit  # noqa: E402
from engine.celery_app import app  # noqa: E402

PALIERS = [8, 16, 32, 64]
PAR_PALIER = 24                      # hosts riches deep-crawlés par palier
LAT_SPIKE_FACTOR = 2.0              # p95 qui double vs palier de base = throttle/tarpit


def _args(argv):
    o = {"file": None, "paliers": PALIERS, "par": PAR_PALIER, "force": False}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--file":
            o["file"] = argv[i + 1]; i += 2
        elif a == "--paliers":
            o["paliers"] = [int(x) for x in argv[i + 1].split(",")]; i += 2
        elif a == "--par-palier":
            o["par"] = int(argv[i + 1]); i += 2
        elif a == "--force-sans-rotation":
            o["force"] = True; i += 1
        else:
            i += 1
    return o


def _step0_rotation(force):
    """Garde-fou dur VPN-AWARE : pas d'escalade sans rotation d'IP ACTIVE.
    Satisfait par IVPN connecté (vérif RÉELLE `ivpn status`) OU proxy-URL branché."""
    if ratelimit.RECON_PROXY:
        print("STEP 0 ✓ rotation active : proxy-URL branché (RECON_PROXY=%s)" % ratelimit.RECON_PROXY)
        return True
    if ratelimit.ivpn_connecte():
        print("STEP 0 ✓ rotation active : IVPN CONNECTÉ (vérifié via `%s`)" % ratelimit.IVPN_STATUS_CMD)
        return True
    print("=" * 74)
    print("STEP 0 ✗ AUCUNE rotation d'IP active (IVPN non connecté ET RECON_PROXY vide).")
    print("Ce protocole pousse jusqu'à faire réagir le WAF. Sans rotation, l'escalade")
    print("BRÛLE l'IP de recon (ban scope-wide) AVANT le rush.")
    print("→ Escalade REFUSÉE. Connecte IVPN (`ivpn connect ...`) ou branche RECON_PROXY.")
    print("  (Override explicite : --force-sans-rotation, paliers très prudents, à tes risques.)")
    print("=" * 74)
    return bool(force)


def _lot(hosts, palier, par):
    """Lot de ce palier : 'par' hosts, mais borné par le nb de FILIALES distinctes
    disponibles (RL_FILIALE_MAX_HOSTS=1) et par le palier lui-même."""
    vus_fil, lot = set(), []
    for h in hosts:
        f = ratelimit.filiale_of(h)
        if f in vus_fil:
            continue
        vus_fil.add(f); lot.append(h)
        if len(lot) >= min(par, palier):
            break
    return lot


def _mesure_palier(lot, palier):
    ratelimit.set_global_max_hosts(palier)
    ratelimit.reset_instrumentation()
    t0 = time.time()
    res = [app.send_task("discover_deep", args=[h]) for h in lot]
    while not all(r.ready() for r in res) and time.time() - t0 < 3600:
        time.sleep(5)
    dt = time.time() - t0
    finis = sum(1 for r in res if r.successful())
    s = ratelimit.stats()
    return {
        "palier": palier, "hosts_lot": len(lot), "finis": finis,
        "duree_s": round(dt), "hosts_h": round(finis / (dt / 3600.0), 1) if dt else 0,
        "req_s_pic": s["rps_pic"], "lat_p50": s["lat_p50_ms"], "lat_p95": s["lat_p95_ms"],
        "sig_429": s["sig_429"], "sig_challenge": s["sig_challenge"],
        "waf_403path": s["waf_par_statut"].get(403, 0),
    }


def _signal_debit(row, base_p95, base_403):
    raisons = []
    if row["sig_429"] > 0:
        raisons.append("429=%d" % row["sig_429"])
    if row["sig_challenge"] > 0:
        raisons.append("challenge=%d" % row["sig_challenge"])
    if base_403 is not None and row["waf_403path"] > base_403 * 1.5 + 2:
        raisons.append("403 ESCALADE %d->%d" % (base_403, row["waf_403path"]))
    if base_p95 and row["lat_p95"] > base_p95 * LAT_SPIKE_FACTOR:
        raisons.append("p95 %sms->%sms" % (base_p95, row["lat_p95"]))
    return raisons


def projection(hosts_h_shallow, hosts_h_deep, part_deep=0.10, total=48000, fenetre_h=72):
    """48k shallow + top-tier deep tiennent-ils en `fenetre_h` heures ?"""
    n_deep = int(total * part_deep)
    t_sh = total / max(1, hosts_h_shallow)
    t_dp = n_deep / max(1, hosts_h_deep)
    return {"n_deep": n_deep, "t_shallow_h": round(t_sh, 1), "t_deep_h": round(t_dp, 1),
            "total_h": round(t_sh + t_dp, 1), "tient_en_72h": (t_sh + t_dp) <= fenetre_h}


def main(argv):
    o = _args(argv)
    if not _step0_rotation(o["force"]):
        return 2
    hosts = ([l.strip().lower() for l in Path(o["file"]).read_text().splitlines() if l.strip()]
             if o["file"] else [])
    if not hosts:
        print("\n(aucun host fourni — --file hosts_riches.txt requis pour escalader)")
        return 1

    print("\n=== CALIBRATION | paliers=%s | %d hosts riches | filiales distinctes=%d ==="
          % (o["paliers"], len(hosts), len({ratelimit.filiale_of(h) for h in hosts})))
    print("%-7s %-8s %-8s %-8s %-8s %-6s %-6s %-9s %s"
          % ("palier", "hosts/h", "req/s", "p50ms", "p95ms", "429", "chall", "403path", "PROPRE?"))
    rows, base_p95, base_403, plafond = [], None, None, None
    for L in o["paliers"]:
        lot = _lot(hosts, L, o["par"])
        row = _mesure_palier(lot, L)
        raisons = _signal_debit(row, base_p95, base_403)
        propre = not raisons
        rows.append((row, propre, raisons))
        print("%-7d %-8s %-8s %-8s %-8s %-6d %-6d %-9d %s"
              % (L, row["hosts_h"], row["req_s_pic"], row["lat_p50"], row["lat_p95"],
                 row["sig_429"], row["sig_challenge"], row["waf_403path"],
                 "OUI" if propre else "STOP:" + ",".join(raisons)))
        if not propre:
            print("\n→ SIGNAL DÉBIT au palier %d. STOP (ne pas pousser = le ban)." % L)
            break
        plafond = L
        base_p95 = base_p95 or row["lat_p95"]
        base_403 = row["waf_403path"] if base_403 is None else base_403

    if plafond:
        rush = int(plafond * 0.8)
        print("\nPLAFOND propre = %d | rush recommandé ~80%% = RL_GLOBAL_MAX_HOSTS≈%d "
              "(CELERY_CONCURRENCY≥%d, RECON_RATE_LIMIT=5, RL_FILIALE_MAX_HOSTS=1)"
              % (plafond, rush, plafond))
        hh = next(r["hosts_h"] for r, p, _ in rows if r["palier"] == plafond)
        pj = projection(hh, hh)   # deep hosts/h ~ shallow ordre de grandeur ; ajuster mesuré
        print("Projection @plafond : shallow 48k=%sh + deep(%d)=%sh = %sh -> tient en 72h : %s"
              % (pj["t_shallow_h"], pj["n_deep"], pj["t_deep_h"], pj["total_h"], pj["tient_en_72h"]))
    ratelimit.set_global_max_hosts(ratelimit.RL_GLOBAL_MAX_HOSTS)  # restaure le défaut
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
