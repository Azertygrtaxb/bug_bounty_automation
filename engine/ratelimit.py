"""Contrôle CENTRAL du débit sortant (§6) — le kit de survie du rush.

Tout ce qui est SORTANT passe (autant que possible) par ce module :
  - token-bucket Redis atomique (Lua) : cap GLOBAL req/s + cap PAR-FILIALE req/s ;
  - slots de concurrence : plafond de hosts DISTINCTS simultanés (global) et par
    FILIALE/infra (ne jamais marteler la même plage IP/WAF) ;
  - verrou PAR-HOST : jamais deux workers sur le même host à la fois ;
  - point d'accroche PROXY (egress) pour brancher des IPs tournantes ;
  - instrumentation : req/s réel (egress Python) + réponses WAF (403/429/challenge).

Le token-bucket gate PRÉCISÉMENT l'egress Python (sonde probe.py). Les binaires recon
(httpx/katana) font leurs propres requêtes : ils sont bornés STRUCTURELLEMENT par
(slots de concurrence) × (-rate-limit conservateur par host), et on VÉRIFIE via les
réponses WAF observées. Défauts CONSERVATEURS, tous éditables par variable d'env.
"""
import json
import os
import subprocess
import time
import urllib.request

import redis

REDIS_URL = os.environ.get("RATELIMIT_REDIS_URL") or os.environ["CELERY_BROKER_URL"]

# --- Défauts CONSERVATEURS (éditables via env) --------------------------------
RL_GLOBAL_RPS       = float(os.environ.get("RL_GLOBAL_RPS", "5"))     # cap global req/s (egress Python)
RL_FILIALE_RPS      = float(os.environ.get("RL_FILIALE_RPS", "2"))    # cap req/s par filiale/infra
RL_GLOBAL_MAX_HOSTS = int(os.environ.get("RL_GLOBAL_MAX_HOSTS", "4")) # hosts distincts simultanés (global)
RL_FILIALE_MAX_HOSTS = int(os.environ.get("RL_FILIALE_MAX_HOSTS", "1")) # hosts simultanés par filiale
RL_HOST_LOCK_TTL    = int(os.environ.get("RL_HOST_LOCK_TTL", "1800")) # s : expiry de sécurité du verrou host
RL_SLOT_TTL         = int(os.environ.get("RL_SLOT_TTL", "1800"))      # s : expiry de sécurité d'un slot (task crashée)
RL_BURST_FACTOR     = float(os.environ.get("RL_BURST_FACTOR", "1"))   # burst = rate * facteur
RL_MAX_WAIT         = float(os.environ.get("RL_MAX_WAIT", "5"))       # s : plafond d'un sleep de throttle

# Point d'accroche PROXY egress (recon). Vide = pas de proxy-URL. Brancher ici un
# proxy-URL de rotation ; OU utiliser IVPN machine-wide (transparent, ci-dessous).
RECON_PROXY = os.environ.get("RECON_PROXY", "").strip()

# --- Rotation d'IP : IVPN machine-wide (transparent) OU proxy-URL --------------
IVPN_STATUS_CMD = os.environ.get("IVPN_STATUS_CMD", "ivpn status")   # vérif RÉELLE
ROTATE_CMD = os.environ.get("RECON_ROTATE_CMD", "").strip()          # ex: engine/proxy/rotate-egress.sh
ROTATION_TEST_URL = os.environ.get("ROTATION_TEST_URL", "https://api.ipify.org")  # URL NEUTRE (IP brute)
SEUIL_ROTATION = int(os.environ.get("SEUIL_ROTATION", "3"))          # K événements débit / fenêtre -> rote
ROTATION_FENETRE_S = int(os.environ.get("ROTATION_FENETRE_S", "120"))

# Overrides d'infra partagée (éditable) : host/suffixe -> clé filiale forcée.
FILIALE_OVERRIDES = {}

_PREFIX = "rl:"
_r = None

# Token-bucket atomique : refill paresseux + prise. Renvoie le temps d'attente (s)
# avant de pouvoir prendre n jetons (0 = pris tout de suite).
_LUA_BUCKET = """
local key=KEYS[1]
local rate=tonumber(ARGV[1]); local burst=tonumber(ARGV[2])
local now=tonumber(ARGV[3]); local n=tonumber(ARGV[4])
local h=redis.call('HMGET', key, 'tokens', 'ts')
local tokens=tonumber(h[1]); local ts=tonumber(h[2])
if tokens==nil then tokens=burst; ts=now end
tokens=math.min(burst, tokens + math.max(0, now-ts)*rate)
local wait=0
if tokens>=n then tokens=tokens-n else wait=(n-tokens)/rate end
redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
redis.call('PEXPIRE', key, 120000)
return tostring(wait)
"""

# Acquisition d'un slot de concurrence (ZSET host->ts). Prune le périmé, plafonne le
# cardinal. Renvoie 1 si acquis (ou déjà tenu, rafraîchi), 0 si plein.
_LUA_SLOT = """
local key=KEYS[1]
local host=ARGV[1]; local cap=tonumber(ARGV[2]); local now=tonumber(ARGV[3]); local ttl=tonumber(ARGV[4])
redis.call('ZREMRANGEBYSCORE', key, 0, now-ttl)
if redis.call('ZSCORE', key, host) then redis.call('ZADD', key, now, host); return 1 end
if redis.call('ZCARD', key) < cap then redis.call('ZADD', key, now, host); return 1 end
return 0
"""


def r():
    global _r
    if _r is None:
        _r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    return _r


# --- Filiale / infra ----------------------------------------------------------
def filiale_of(host):
    """Clé d'infra partagée = domaine enregistré (eTLD+1 simplifié : 2 derniers
    labels). Regroupe tous les sous-domaines d'une société = même WAF/plage IP.
    Overrides éditables pour infra mutualisée connue."""
    h = (host or "").strip().lower().rstrip(".")
    for suf, fil in FILIALE_OVERRIDES.items():
        if h == suf or h.endswith("." + suf):
            return fil
    labels = h.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else h


# --- Token-bucket : throttle egress ------------------------------------------
def _take(key, rate, n=1):
    burst = max(1.0, rate * RL_BURST_FACTOR)
    return float(r().eval(_LUA_BUCKET, 1, _PREFIX + "tb:" + key, rate, burst, time.time(), n))


def throttle_egress(host):
    """Bloque (sleeps bornés) jusqu'à disposer d'un jeton GLOBAL ET d'un jeton
    FILIALE. À appeler avant CHAQUE requête sortante Python (sonde)."""
    fil = filiale_of(host)
    for key, rate in (("global", RL_GLOBAL_RPS), ("fil:" + fil, RL_FILIALE_RPS)):
        while True:
            wait = _take(key, rate)
            if wait <= 0:
                break
            time.sleep(min(wait, RL_MAX_WAIT))


# --- Slots de concurrence + verrou host --------------------------------------
def acquire_slot(scope_key, host, cap):
    return int(r().eval(_LUA_SLOT, 1, _PREFIX + "slot:" + scope_key, host, cap, time.time(), RL_SLOT_TTL)) == 1


def release_slot(scope_key, host):
    r().zrem(_PREFIX + "slot:" + scope_key, host)


def acquire_host_lock(host):
    return bool(r().set(_PREFIX + "lock:" + host, str(time.time()), nx=True, ex=RL_HOST_LOCK_TTL))


def release_host_lock(host):
    r().delete(_PREFIX + "lock:" + host)


def global_max_hosts():
    """Cap global de hosts simultanés, pilotable À CHAUD (Redis) pour la calibration
    par paliers ; défaut = RL_GLOBAL_MAX_HOSTS (env). RL_FILIALE_MAX_HOSTS reste fixe."""
    v = r().get(_PREFIX + "cfg:global_max_hosts")
    return int(v) if v else RL_GLOBAL_MAX_HOSTS


def set_global_max_hosts(n):
    r().set(_PREFIX + "cfg:global_max_hosts", int(n))


def acquire_host_pour_recon(host):
    """Admission d'un host en recon : verrou host + slot filiale + slot global.
    Tout-ou-rien : si un cran manque, on relâche ce qu'on a pris et on renvoie
    (False, raison) pour que la task RETENTE plus tard (ne bloque pas un worker)."""
    if est_en_rotation():                     # rotation machine-wide en cours -> on attend
        return False, "rotation_en_cours"
    fil = filiale_of(host)
    if not acquire_host_lock(host):
        return False, "host_deja_en_cours"
    if not acquire_slot("fil:" + fil, host, RL_FILIALE_MAX_HOSTS):
        release_host_lock(host)
        return False, "slot_filiale_plein:" + fil
    if not acquire_slot("global", host, global_max_hosts()):
        release_slot("fil:" + fil, host)
        release_host_lock(host)
        return False, "slot_global_plein"
    return True, "ok"


def liberer_host(host):
    fil = filiale_of(host)
    release_slot("global", host)
    release_slot("fil:" + fil, host)
    release_host_lock(host)


# --- Instrumentation : req/s réel + réponses WAF ------------------------------
def record_request(host):
    """Compteur egress par seconde (fenêtre glissante ~2 min)."""
    sec = int(time.time())
    k = _PREFIX + "rps:%d" % sec
    p = r().pipeline()
    p.incr(k)
    p.expire(k, 120)
    p.incr(_PREFIX + "req_total")
    p.execute()


def record_waf(host, status, url):
    """Log une réponse type WAF (403/429/challenge) sur un endpoint SCANNÉ (pas la
    home) — le signal qu'on approche du ban."""
    r().rpush(_PREFIX + "waf", json.dumps(
        {"host": host, "status": status, "url": url, "ts": int(time.time())}))
    r().ltrim(_PREFIX + "waf", -500, -1)


def est_reponse_waf(status, url):
    """403/429 (ou challenge) sur un chemin NON-racine = signal WAF."""
    if status not in (403, 429):
        return False
    from urllib.parse import urlsplit
    path = (urlsplit(url or "").path or "/").rstrip("/")
    return path not in ("", "/")


# --- Signaux de PLAFOND (blocage par DÉBIT) + latence : pour la calibration -----
import re as _re  # noqa: E402
_CHALLENGE = _re.compile(
    r"(captcha|challenge-platform|cf[-_]challenge|/cdn-cgi/challenge|hcaptcha"
    r"|recaptcha|are you human|verifying you are|access denied.*rate)", _re.I)


def est_signal_debit(status, body):
    """Distingue un blocage par DÉBIT (429 / challenge injecté) du 403 par-chemin
    bénin (règle de contenu stable). Renvoie '429' | 'challenge' | None."""
    if status == 429:
        return "429"
    if body and _CHALLENGE.search(body):
        return "challenge"
    return None


def record_latency(ms):
    cli = r()
    cli.rpush(_PREFIX + "lat", float(ms))
    cli.ltrim(_PREFIX + "lat", -5000, -1)


def record_signal(kind):
    """Compteur de signal débit ('429'|'challenge'|'403path')."""
    r().incr(_PREFIX + "sig:" + kind)


def _percentile(vals, p):
    if not vals:
        return 0
    xs = sorted(vals)
    i = min(len(xs) - 1, int(round((p / 100.0) * (len(xs) - 1))))
    return round(xs[i], 1)


def stats(fenetre_s=120):
    """Métriques brutes : req/s pic/moyen (egress Python) sur la fenêtre, total,
    hits WAF, hosts actifs (global + par filiale)."""
    now = int(time.time())
    cli = r()
    per_sec = []
    for s in range(now - fenetre_s, now + 1):
        v = cli.get(_PREFIX + "rps:%d" % s)
        per_sec.append(int(v) if v else 0)
    actifs_nonzero = [x for x in per_sec if x > 0]
    waf = [json.loads(x) for x in cli.lrange(_PREFIX + "waf", 0, -1)]
    slots_global = cli.zrange(_PREFIX + "slot:global", 0, -1)
    fil_keys = cli.keys(_PREFIX + "slot:fil:*")
    fil = {k.split("slot:fil:")[-1]: cli.zcard(k) for k in fil_keys}
    lat = [float(x) for x in cli.lrange(_PREFIX + "lat", 0, -1)]
    return {
        "req_total_egress": int(cli.get(_PREFIX + "req_total") or 0),
        "rps_pic": max(per_sec) if per_sec else 0,
        "rps_moyen_actif": round(sum(actifs_nonzero) / len(actifs_nonzero), 2) if actifs_nonzero else 0,
        "secondes_actives": len(actifs_nonzero),
        "lat_p50_ms": _percentile(lat, 50),
        "lat_p95_ms": _percentile(lat, 95),
        "waf_hits": len(waf),
        "waf_par_host": _compte([w["host"] for w in waf]),
        "waf_par_statut": _compte([w["status"] for w in waf]),
        # signaux DÉBIT (plafond) séparés du 403 par-chemin bénin :
        "sig_429": int(cli.get(_PREFIX + "sig:429") or 0),
        "sig_challenge": int(cli.get(_PREFIX + "sig:challenge") or 0),
        "hosts_actifs_global": list(slots_global),
        "hosts_actifs_par_filiale": {k: v for k, v in fil.items() if v},
    }


# --- A1 : ROTATION D'IP ACTIVE (IVPN machine-wide OU proxy-URL) — vérif RÉELLE ---
def _parse_ivpn_status(text):
    """True si la sortie `ivpn status` indique une connexion active. « Disconnected »
    ne matche pas (frontière : le 'c' de …connected y est précédé d'une lettre)."""
    import re
    return bool(re.search(r"(?<![a-z])connected\b", text or "", re.I))


def ivpn_connecte():
    """Vérif RÉELLE (pas un flag) : exécute `ivpn status` et parse « Connected ».
    False si ivpn absent (ex. dans le conteneur : la vérif se fait côté hôte)."""
    try:
        out = subprocess.run(IVPN_STATUS_CMD.split(), capture_output=True,
                             text=True, timeout=8)
        return _parse_ivpn_status((out.stdout or "") + " " + (out.stderr or ""))
    except Exception:
        return False


def rotation_active():
    """Rotation d'IP disponible = IVPN connecté OU proxy-URL branché (l'un OU l'autre)."""
    return bool(RECON_PROXY) or ivpn_connecte()


# --- A2 : SIGNAL WAF -> ROTATION (réactif au crawl réel) -----------------------
def est_en_rotation():
    return r().get(_PREFIX + "rotating") == "1"


def _exit_ip():
    """Sonde l'IP de sortie via une URL NEUTRE (jamais une cible). (status, ip|err)."""
    try:
        req = urllib.request.Request(ROTATION_TEST_URL,
                                     headers={"User-Agent": "bb-egress-check"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status, resp.read(200).decode("utf-8", "replace").strip()
    except Exception as e:
        return None, ("err:" + type(e).__name__)


def enregistrer_evenement_debit():
    """Ajoute un événement débit dans la fenêtre glissante ; renvoie le compte."""
    now = time.time()
    cli = r()
    cli.zadd(_PREFIX + "debit_ev", {"%f" % now: now})
    cli.zremrangebyscore(_PREFIX + "debit_ev", 0, now - ROTATION_FENETRE_S)
    return cli.zcard(_PREFIX + "debit_ev")


def rotate_egress():
    """Rotation d'IP réactive : pause admission -> rotation IVPN -> probe -> reprise.
    Verrou pour qu'UNE seule rotation tourne (événement machine-wide). Renvoie le détail."""
    cli = r()
    if not cli.set(_PREFIX + "rotate_lock", "1", nx=True, ex=180):
        return {"skipped": "rotation_deja_en_cours"}
    try:
        cli.set(_PREFIX + "rotating", "1")           # 1) PAUSE admission (tous workers)
        st0, ip0 = _exit_ip()
        if ROTATE_CMD:                               # 2) rotation IVPN (disconnect->connect pays frais)
            try:
                p = subprocess.run(ROTATE_CMD.split(), capture_output=True,
                                   text=True, timeout=180)
                cmd_out = ((p.stdout or "") + (p.stderr or "")).strip()[-200:]
            except Exception as e:
                cmd_out = "echec rotate cmd: %s" % e
        else:
            cmd_out = "(RECON_ROTATE_CMD vide : rotation non exécutée — mode test)"
        st1, ip1 = _exit_ip()                         # 3) vérif reconnexion (200 + IP changée)
        cli.zremrangebyscore(_PREFIX + "debit_ev", 0, time.time())  # vide la fenêtre
        return {"ip_avant": ip0, "http_avant": st0, "ip_apres": ip1, "http_apres": st1,
                "ip_change": bool(ip0 and ip1 and ip0 != ip1 and st1 == 200),
                "rotate_cmd": ROTATE_CMD or None, "cmd_out": cmd_out}
    finally:
        cli.set(_PREFIX + "rotating", "0")            # 4) reprise
        cli.delete(_PREFIX + "rotate_lock")


def signal_debit_et_evaluer(kind):
    """Enregistre un signal débit ; si le seuil est franchi dans la fenêtre -> rote.
    Déclencheur PRIMAIRE de rotation (le cron groupebpce reste un filet de sécurité)."""
    record_signal(kind)
    n = enregistrer_evenement_debit()
    if n >= SEUIL_ROTATION and not est_en_rotation():
        return {"evenements_fenetre": n, "seuil": SEUIL_ROTATION, "rote": True,
                "rotation": rotate_egress()}
    return {"evenements_fenetre": n, "seuil": SEUIL_ROTATION, "rote": False}


def reset_instrumentation():
    cli = r()
    for k in cli.keys(_PREFIX + "rps:*") + cli.keys(_PREFIX + "sig:*"):
        cli.delete(k)
    cli.delete(_PREFIX + "req_total", _PREFIX + "waf", _PREFIX + "lat",
               _PREFIX + "debit_ev")


def _compte(xs):
    d = {}
    for x in xs:
        d[x] = d.get(x, 0) + 1
    return d
