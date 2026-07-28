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

Exposition : par défaut BOARD_EXPOSE=0 -> accès localhost/tunnel SSH, auth optionnelle
(sauf /api/lead/detail, toujours protégé). BOARD_EXPOSE=1 -> auth OBLIGATOIRE partout,
refuse de démarrer si BOARD_PASS vide.
"""
import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from engine import leads          # noqa: E402
from knowledge import config      # noqa: E402

HTML = Path(__file__).resolve().parent / "board.html"
PORT = int(os.environ.get("BOARD_PORT", "8080"))
BIND = os.environ.get("BOARD_BIND", "0.0.0.0")  # publish côté host contrôle l'exposition réelle
EXPOSE = os.environ.get("BOARD_EXPOSE", "0").lower() in ("1", "true", "yes", "on")
USER = os.environ.get("BOARD_USER", "")
PASS = os.environ.get("BOARD_PASS", "")
AUTH_CONFIGUREE = bool(USER and PASS)


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
    for r in rows:
        if host and r.get("host") != host:
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


def _json_default(o):
    if isinstance(o, datetime):
        return o.isoformat()
    if isinstance(o, frozenset):
        return list(o)
    return str(o)


class Handler(BaseHTTPRequestHandler):
    server_version = "board/1.0"

    # --- utilitaires réponse ---
    def _envoyer(self, code, corps, ctype="application/json"):
        data = corps if isinstance(corps, bytes) else json.dumps(
            corps, default=_json_default, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _auth_ok(self):
        h = self.headers.get("Authorization", "")
        if not h.startswith("Basic ") or not AUTH_CONFIGUREE:
            return False
        try:
            u, _, p = base64.b64decode(h[6:]).decode("utf-8").partition(":")
        except Exception:
            return False
        return u == USER and p == PASS

    def _exiger_auth(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="board"')
        self.end_headers()

    def _garde(self, sensible=False):
        """True si la requête peut continuer. `sensible` (détail) -> auth TOUJOURS exigée.
        Sinon auth exigée seulement en mode exposé."""
        if sensible:
            if not AUTH_CONFIGUREE:
                self._envoyer(503, {"erreur": "auth requise pour le détail : configurer "
                                    "BOARD_USER/BOARD_PASS"})
                return False
            if not self._auth_ok():
                self._exiger_auth()
                return False
            return True
        if EXPOSE and not self._auth_ok():
            self._exiger_auth()
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
            if not self._garde(sensible=True):   # R2 : toujours derrière auth
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
                "nouveaux_24h": n24, "nouveaux_7j": n7}

    # --- écriture (leads_statut uniquement) ---
    def do_POST(self):
        u = urlsplit(self.path)
        if u.path != "/api/leads/statut":
            return self._envoyer(404, {"erreur": "route inconnue"})
        if not self._garde():
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, json.JSONDecodeError):
            return self._envoyer(400, {"erreur": "JSON invalide"})
        host, pattern, statut = body.get("host"), body.get("pattern"), body.get("statut")
        if not host or not pattern or not statut:
            return self._envoyer(400, {"erreur": "host, pattern et statut obligatoires"})
        try:
            leads.marquer(host, pattern, statut, body.get("note"))
        except ValueError as e:
            return self._envoyer(400, {"erreur": str(e)})
        return self._envoyer(200, {"ok": True, "host": host, "pattern": pattern, "statut": statut})


def main():
    if EXPOSE and not PASS:
        sys.stderr.write("[board] REFUS de démarrer : BOARD_EXPOSE=1 sans BOARD_PASS "
                         "(auth obligatoire en mode exposé).\n")
        return 2
    mode = "EXPOSÉ (auth obligatoire)" if EXPOSE else "localhost/tunnel (auth %s)" % (
        "activée" if AUTH_CONFIGUREE else "optionnelle ; détail protégé")
    sys.stderr.write("[board] http://%s:%d  — %s\n" % (BIND, PORT, mode))
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
