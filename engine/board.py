"""DASHBOARD de chasse (Tier 4) — LIT `leads`, ÉCRIT `leads_statut`. Ne rescore jamais,
ne relance jamais de recon, ne touche jamais `targets` (sauf lecture).

Serveur stdlib (http.server) : zéro dépendance, zéro build. On assume les migrations
jouées (aucun DDL depuis ce process : il tourne avec un rôle postgres SELECT + INSERT/
UPDATE sur leads_statut seulement — voir README « rôle board_ro »).

    GET  /                    page HTML
    GET  /api/leads           lire(seuil, quota) filtré (min_score/host/statut/in_scope/q/
                              nouveaux_depuis/quota)
    GET  /api/leads/masques   ?host= : les leads masqués par le quota (le « +N autres »)
    POST /api/leads/statut    {host,pattern,statut,note} -> marquer() (400 si statut invalide)
    GET  /api/lead/detail     ?host=&pattern= : membres réels + raisons + headers + extrait
                              corps (LECTURE SEULE, TOUJOURS derrière auth — données sensibles)
    GET  /api/orphelins       statuts orphelins (travail humain à re-router)
    GET  /api/stats           compteurs (total, par statut, par host top10, nouveaux 24h/7j)

Sécurité : login OBLIGATOIRE partout (board PARTAGÉ, ≥2 comptes via BOARD_ACCOUNTS
'alice:passA,bob:passB') — refuse de démarrer sans compte. Comparaison timing-safe.
POST protégé CSRF (en-tête custom X-Board + Origin même hôte). Chaque statut trace QUI
l'a posé (par_qui). BOARD_EXPOSE=0 (défaut) publie sur 127.0.0.1 (tunnel SSH) ; =1 bind
0.0.0.0 (login déjà obligatoire de toute façon).
"""
import base64
import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine import leads          # noqa: E402
from knowledge import config      # noqa: E402

HTML = Path(__file__).resolve().parent / "board.html"
PORT = int(os.environ.get("BOARD_PORT", "8080"))
EXPOSE = os.environ.get("BOARD_EXPOSE", "0").lower() in ("1", "true", "yes", "on")
# EXPOSE=1 -> écoute 0.0.0.0 DANS le conteneur (joignable par Caddy sur le réseau Docker,
# OU par un port publié). EXPOSE=0 -> 127.0.0.1 (dev local hors docker). BOARD_BIND force.
BIND = os.environ.get("BOARD_BIND") or ("0.0.0.0" if EXPOSE else "127.0.0.1")
PBKDF2_ITERS = int(os.environ.get("BOARD_PBKDF2_ITERS", "600000"))

# Réseaux de confiance pour X-Forwarded-For (E3), pré-compilés une fois.
_RESEAUX_CONFIANCE = []
for _c in config.PROXIES_DE_CONFIANCE:
    try:
        _RESEAUX_CONFIANCE.append(ipaddress.ip_network(_c, strict=False))
    except ValueError:
        pass


def _est_proxy_confiance(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _RESEAUX_CONFIANCE)


def _parse_comptes(raw, legacy_user, legacy_pass):
    """BOARD_ACCOUNTS='alice:<secret>,bob:<secret>' -> {user: secret}. Le <secret> est soit
    un hash 'pbkdf2$<iter>$<salt_b64>$<hash_b64>', soit un mot de passe en CLAIR (rétro-compat,
    averti au démarrage). Le split se fait sur le 1er ':' (le hash n'en contient pas)."""
    comptes = {}
    for pair in (raw or "").split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        u, _, secret = pair.partition(":")
        u, secret = u.strip(), secret.strip()
        if u and secret:
            comptes[u] = secret
    if legacy_user and legacy_pass:
        comptes.setdefault(legacy_user.strip(), legacy_pass)
    return comptes


COMPTES = _parse_comptes(os.environ.get("BOARD_ACCOUNTS", ""),
                         os.environ.get("BOARD_USER", ""), os.environ.get("BOARD_PASS", ""))


# Pourquoi hacher alors que le VPS a déjà la base ? Le risque n'est PAS le VPS compromis
# (qui a la base a tout de toute façon) : c'est la RÉUTILISATION du mot de passe ailleurs.
# Un mot de passe en clair dans .env/l'environnement fuite un secret réutilisé (mail, VPN…) ;
# un hash pbkdf2 ne le fuite pas.
def _est_hache(secret):
    return secret.startswith("pbkdf2$")


def _verifie_secret(pwd, secret):
    """TIMING-SAFE. Vérifie `pwd` contre un secret haché (pbkdf2$iter$salt$hash) OU en clair."""
    if _est_hache(secret):
        try:
            _, iters, salt_b64, hash_b64 = secret.split("$")
            salt, attendu = base64.b64decode(salt_b64), base64.b64decode(hash_b64)
            got = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, int(iters))
            return hmac.compare_digest(got, attendu)
        except Exception:
            return False
    return hmac.compare_digest(pwd, secret)


def _verifier(user, pwd):
    """True si (user, pwd) valide. User inconnu -> calcul bidon pour lisser le timing."""
    secret = COMPTES.get(user)
    if secret is None:
        hashlib.pbkdf2_hmac("sha256", b"x", b"x", PBKDF2_ITERS)  # anti-énumération par timing
        return False
    return _verifie_secret(pwd, secret)


def _fabriquer_hash(pwd):
    """pwd -> 'pbkdf2$<iter>$<salt_b64>$<hash_b64>'. Sel aléatoire (os.urandom)."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, PBKDF2_ITERS)
    return "pbkdf2$%d$%s$%s" % (PBKDF2_ITERS, base64.b64encode(salt).decode(),
                                base64.b64encode(dk).decode())


# --- Journal d'authentification (stderr, une ligne horodatée par événement) ----------
def _journal(msg):
    sys.stderr.write("%s [board] %s\n" % (datetime.now(timezone.utc).isoformat(timespec="seconds"), msg))
    sys.stderr.flush()


# --- Anti-bruteforce : compteur d'échecs par (user, IP), en mémoire (process long-vivant) --
_ECHECS = {}
_ECHECS_LOCK = threading.Lock()


def _retry_si_bloque(user, ip):
    """Secondes de Retry-After si (user, ip) dépasse le seuil dans la fenêtre, sinon 0."""
    maxi, fen = config.BOARD_MAX_ECHECS, config.BOARD_FENETRE_ECHECS
    now = time.monotonic()
    with _ECHECS_LOCK:
        ts = [t for t in _ECHECS.get((user, ip), []) if now - t < fen]
        _ECHECS[(user, ip)] = ts
        if len(ts) >= maxi:
            return int(fen - (now - ts[0])) + 1
    return 0


def _note_echec(user, ip):
    with _ECHECS_LOCK:
        _ECHECS.setdefault((user, ip), []).append(time.monotonic())


def _reset_echecs(user, ip):
    with _ECHECS_LOCK:
        _ECHECS.pop((user, ip), None)


def _decode_basic(h):
    """En-tête Authorization -> (user, pwd) ou (None, None)."""
    if not h.startswith("Basic "):
        return None, None
    try:
        u, _, p = base64.b64decode(h[6:]).decode("utf-8").partition(":")
        return u, p
    except Exception:
        return None, None


def _now():
    return datetime.now(timezone.utc)


def _parse_depuis(v):
    """'24h' / '7j' / '7d' / ISO date -> datetime aware. None si vide/illisible."""
    if not v:
        return None
    v = v.strip().lower()
    try:
        if v.endswith("h"):
            return _now() - timedelta(hours=float(v[:-1]))
        if v.endswith(("j", "d")):
            return _now() - timedelta(days=float(v[:-1]))
        dt = datetime.fromisoformat(v)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _filtrer(rows, host=None, statut=None, in_scope=None, q=None, depuis=None):
    out = []
    hostl = host.lower() if host else None
    for r in rows:
        if hostl and hostl not in (r.get("host") or "").lower():   # substring, insensible à la casse
            continue
        if statut and r.get("statut") != statut:
            continue
        if in_scope is not None and bool(r.get("in_scope")) != in_scope:
            continue
        if q:
            hay = " ".join(str(r.get(k) or "") for k in ("host", "pattern", "url_representative"))
            if q.lower() not in hay.lower():
                continue
        if depuis is not None:
            pv = r.get("premiere_vue")
            if pv is None or pv < depuis:
                continue
        out.append(r)
    return out


def _agreger_hosts(rows):
    """G1 — une ligne par host à partir des MÊMES leads (déjà filtrés). Aucune ligne
    'repli' (appelé sur quota=False). Tri : score_max DESC puis nb_leads DESC."""
    s24 = _now() - timedelta(hours=24)
    par = {}
    for r in rows:
        h = r.get("host")
        g = par.get(h)
        if g is None:
            g = par[h] = {"host": h, "nb_leads": 0, "score_max": 0, "nb_nouveaux": 0,
                          "statuts": {s: 0 for s in config.STATUTS_LEAD},
                          "url_representative": None, "_tech": Counter(), "_smax": -1}
        g["nb_leads"] += 1
        sc = r.get("score") or 0
        if sc > g["_smax"]:
            g["_smax"] = sc
            g["score_max"] = sc
            g["url_representative"] = r.get("url_representative")
        st = r.get("statut") or config.STATUT_DEFAUT
        if st in g["statuts"]:
            g["statuts"][st] += 1
        pv = r.get("premiere_vue")
        if pv is not None and pv >= s24:
            g["nb_nouveaux"] += 1
        for t in (r.get("tech") or []):
            g["_tech"][t] += 1
    out = []
    for g in par.values():
        g["tech"] = [t for t, _ in g["_tech"].most_common(5)]
        del g["_tech"], g["_smax"]
        out.append(g)
    out.sort(key=lambda x: (x["score_max"], x["nb_leads"]), reverse=True)
    return out


def _json_default(o):
    if isinstance(o, datetime):
        return o.isoformat()
    if isinstance(o, frozenset):
        return list(o)
    return str(o)


class Handler(BaseHTTPRequestHandler):
    server_version = "board/1.0"

    # --- utilitaires réponse ---
    _CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'; img-src 'none'; form-action 'none'; frame-ancestors 'none'")

    def _envoyer(self, code, corps, ctype="application/json"):
        data = corps if isinstance(corps, bytes) else json.dumps(
            corps, default=_json_default, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if ctype.startswith("text/html"):   # S4 : verrouille la page (pas d'exfil sortante)
            self.send_header("Content-Security-Policy", self._CSP)
            self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(data)

    def _exiger_auth(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Lead Board"')
        self.end_headers()

    def _ip_client(self):
        """IP RÉELLE du client (sert au comptage anti-bruteforce). Ne fait confiance à
        X-Forwarded-For que si la connexion vient d'un proxy de confiance (§14) ; sinon
        l'en-tête est ignoré (falsifiable par un client direct). Prend la DERNIÈRE valeur
        du XFF = celle ajoutée par le proxy de confiance (le vrai client), pas une valeur
        que le client aurait pré-insérée à gauche."""
        peer = self.client_address[0]
        if _est_proxy_confiance(peer):
            xff = self.headers.get("X-Forwarded-For", "")
            if xff.strip():
                return xff.split(",")[-1].strip()
        return peer

    def _garde(self):
        """Login OBLIGATOIRE partout. Anti-bruteforce (429 avant toute comparaison) +
        journal des échecs/blocages. Renvoie le compte, ou None après avoir répondu."""
        ip = self._ip_client()
        user, pwd = _decode_basic(self.headers.get("Authorization", ""))
        if user is None:
            self._exiger_auth()
            return None
        retry = _retry_si_bloque(user, ip)
        if retry > 0:                                   # bloqué : PAS de comparaison de mdp
            _journal("BLOCAGE user=%s ip=%s retry=%ds" % (user, ip, retry))
            self.send_response(429)
            self.send_header("Retry-After", str(retry))
            self.end_headers()
            return None
        if _verifier(user, pwd):
            _reset_echecs(user, ip)
            return user
        _note_echec(user, ip)
        _journal("ECHEC_LOGIN user=%s ip=%s" % (user, ip))
        self._exiger_auth()
        return None

    def _csrf_ok(self):
        """Anti-CSRF : exige l'en-tête custom X-Board (impossible à poser depuis un
        <form> cross-site sans préflight, non accordé) + Origin/Referer même hôte si
        présent. Le fetch de la page le pose ; un site tiers ne peut pas."""
        if self.headers.get("X-Board", "") != "1":
            return False
        src = self.headers.get("Origin") or self.headers.get("Referer") or ""
        if src:
            net = urlsplit(src).netloc
            if net and self.headers.get("Host") and net != self.headers.get("Host"):
                return False
        return True

    def log_message(self, *a):  # silencieux (pas de log verbeux par requête)
        pass

    # --- lecture ---
    def do_GET(self):
        u = urlsplit(self.path)
        qs = parse_qs(u.query)
        one = lambda k, d=None: qs.get(k, [d])[0]

        if u.path == "/":
            if not self._garde():
                return
            try:
                return self._envoyer(200, HTML.read_bytes(), "text/html")
            except FileNotFoundError:
                return self._envoyer(500, {"erreur": "board.html introuvable"})

        if u.path == "/api/leads":
            if not self._garde():
                return
            seuil = int(one("min_score", "1") or 1)
            quota = one("quota", "1") != "0"
            in_scope = None if one("in_scope") in (None, "") else (one("in_scope") in ("1", "true"))
            rows = leads.lire(seuil, quota=False)
            rows = _filtrer(rows, host=one("host"), statut=one("statut"), in_scope=in_scope,
                            q=one("q"), depuis=_parse_depuis(one("nouveaux_depuis")))
            if quota:
                rows = leads._appliquer_quota(rows)
            return self._envoyer(200, {"count": len(rows), "leads": rows})

        if u.path == "/api/hosts":   # G1 : agrégation par host des MÊMES leads filtrés
            if not self._garde():
                return
            seuil = int(one("min_score", "1") or 1)
            in_scope = None if one("in_scope") in (None, "") else (one("in_scope") in ("1", "true"))
            rows = leads.lire(seuil, quota=False)   # quota inutile ici : le groupement le remplace
            rows = _filtrer(rows, host=one("host"), statut=one("statut"), in_scope=in_scope,
                            q=one("q"), depuis=_parse_depuis(one("nouveaux_depuis")))
            hosts = _agreger_hosts(rows)
            return self._envoyer(200, {"count": len(hosts), "hosts": hosts})

        if u.path == "/api/leads/masques":
            if not self._garde():
                return
            host = one("host")
            if not host:
                return self._envoyer(400, {"erreur": "param host obligatoire"})
            mx = config.MAX_LEADS_PAR_HOST
            rows = [r for r in leads.lire(1, quota=False) if r["host"] == host]
            rows.sort(key=lambda x: (x["score"], x["nb"] or 0), reverse=True)
            masques = rows[mx:] if mx and mx > 0 else []
            return self._envoyer(200, {"host": host, "count": len(masques), "masques": masques})

        if u.path == "/api/lead/detail":
            if not self._garde():   # R2 : données sensibles -> auth (obligatoire partout)
                return
            host, pattern = one("host"), one("pattern")
            if not host or not pattern:
                return self._envoyer(400, {"erreur": "params host et pattern obligatoires"})
            return self._envoyer(200, leads.detail(host, pattern))

        if u.path == "/api/orphelins":
            if not self._garde():
                return
            orph = leads.lister_orphelins()
            return self._envoyer(200, {"count": len(orph), "orphelins": orph})

        if u.path == "/api/stats":
            if not self._garde():
                return
            return self._envoyer(200, self._stats())

        return self._envoyer(404, {"erreur": "route inconnue"})

    def do_HEAD(self):
        """P1 — liveness pour la supervision (curl -I). 200 + en-têtes, AUCUN corps, aucune
        donnée : un simple ping « le board est debout » (avant, HEAD renvoyait 501)."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", "0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", Handler._CSP)
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()

    def _stats(self):
        rows = leads.lire(1, quota=False)
        par_statut, par_host = {}, {}
        n24 = n7 = 0
        s24, s7 = _now() - timedelta(hours=24), _now() - timedelta(days=7)
        for r in rows:
            par_statut[r["statut"]] = par_statut.get(r["statut"], 0) + 1
            par_host[r["host"]] = par_host.get(r["host"], 0) + 1
            pv = r.get("premiere_vue")
            if pv is not None:
                if pv >= s24:
                    n24 += 1
                if pv >= s7:
                    n7 += 1
        top = sorted(par_host.items(), key=lambda kv: kv[1], reverse=True)[:10]
        return {"total": len(rows), "par_statut": par_statut,
                "par_host": [{"host": h, "n": n} for h, n in top],
                "nouveaux_24h": n24, "nouveaux_7j": n7,
                "max_leads_par_groupe": config.AFFICHAGE_MAX_LEADS_PAR_GROUPE}

    # --- écriture (leads_statut uniquement) ---
    def do_POST(self):
        u = urlsplit(self.path)
        if u.path != "/api/leads/statut":
            return self._envoyer(404, {"erreur": "route inconnue"})
        user = self._garde()
        if not user:
            return
        if not self._csrf_ok():
            return self._envoyer(403, {"erreur": "requête inter-site refusée (CSRF)"})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._envoyer(400, {"erreur": "JSON invalide"})
        host, pattern, statut = body.get("host"), body.get("pattern"), body.get("statut")
        if not host or not pattern or not statut:
            return self._envoyer(400, {"erreur": "host, pattern et statut obligatoires"})
        try:
            leads.marquer(host, pattern, statut, body.get("note"), par=user)  # trace QUI
        except ValueError as e:
            return self._envoyer(400, {"erreur": str(e)})
        _journal("STATUT par=%s ip=%s host=%s pattern=%s statut=%s"
                 % (user, self._ip_client(), host, pattern, statut))
        return self._envoyer(200, {"ok": True, "host": host, "pattern": pattern,
                                   "statut": statut, "par": user})


def _outil_hash():
    """python engine/board.py --hash-pass : demande user+mot de passe (sans écho) et
    imprime la ligne hachée à coller dans BOARD_ACCOUNTS."""
    user = input("compte (nom d'utilisateur) : ").strip()
    p1 = getpass.getpass("mot de passe : ")
    p2 = getpass.getpass("confirme : ")
    if not user or not p1:
        sys.stderr.write("compte et mot de passe requis.\n")
        return 2
    if p1 != p2:
        sys.stderr.write("les mots de passe diffèrent.\n")
        return 2
    print("\n# à coller dans BOARD_ACCOUNTS (.env) — séparer les comptes par des virgules :")
    print("%s:%s" % (user, _fabriquer_hash(p1)))
    return 0


def _tester_base():
    """P3 — teste la connexion base UNE fois au boot, message clair au lieu d'une trace
    psycopg brute à chaque requête + 502 côté client. Renvoie None si OK, sinon un message."""
    import psycopg
    user = urlsplit(leads.DATABASE_URL).username or "?"
    try:
        with psycopg.connect(leads.DATABASE_URL, connect_timeout=5) as c, c.cursor() as cur:
            cur.execute("SELECT 1")
        return None
    except psycopg.OperationalError as e:
        m = str(e).lower()
        if "password" in m or "authentication" in m or "role" in m:
            return "identifiants base refusés pour l'utilisateur '%s'" % user
        return "base injoignable (%s)" % str(e).strip().splitlines()[0]


def main():
    if "--hash-pass" in sys.argv[1:]:
        return _outil_hash()
    if not COMPTES:
        sys.stderr.write("[board] REFUS de démarrer : aucun compte. Login OBLIGATOIRE "
                         "(board partagé) -> BOARD_ACCOUNTS='alice:<hash>,bob:<hash>' "
                         "(génère les hash : python engine/board.py --hash-pass).\n")
        return 2
    # P2 : un hash pbkdf2 mal collé (≠ 4 morceaux) produit des 401 muets -> refuse, nomme le compte.
    for u, secret in COMPTES.items():
        if secret.startswith("pbkdf2") and len(secret.split("$")) != 4:
            sys.stderr.write("[board] REFUS de démarrer : le compte '%s' a un hash pbkdf2 "
                             "MALFORMÉ (attendu 'pbkdf2$iter$sel$hash', 4 morceaux ; %d trouvés). "
                             "Regénère : python engine/board.py --hash-pass\n"
                             % (u, len(secret.split("$"))))
            return 2
        if not _est_hache(secret):   # rétro-compat : avertir si un mdp est en clair
            sys.stderr.write("[board] AVERTISSEMENT : le compte '%s' a un mot de passe EN "
                             "CLAIR dans l'environnement. Hache-le : python engine/board.py "
                             "--hash-pass\n" % u)
    # P3 : base testée une fois, message explicite.
    err = _tester_base()
    if err:
        sys.stderr.write("[board] REFUS de démarrer : %s.\n" % err)
        return 2
    mode = "EXPOSÉ (0.0.0.0)" if EXPOSE else "localhost/tunnel"
    sys.stderr.write("[board] http://%s:%d — %s — login obligatoire, %d compte(s)\n"
                     % (BIND, PORT, mode, len(COMPTES)))
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
