"""SCOPE dérivé de la LISTE lancée — PAS d'allowlist à la main.

Le scope = les registered-domains de la liste targets qu'on lance (+ leurs
sous-domaines énumérés, qui partagent le même registered-domain). "Juste BPCE" = la
liste 48k. On dérive SCOPE_ROOTS automatiquement et on le persiste (table scope_roots,
NON effacée par les re-scores).

Un lead est IN-SCOPE si le registered-domain de son host ∈ SCOPE_ROOTS ; sinon (rebond
vers un AUTRE domaine enregistré : vulnweb.com, sarbacane...) -> hors-scope, exclu de
la vue leads (sauf INCLURE_HORS_SCOPE).

Usage :  python engine/scope.py --file targets.txt   # dérive + persiste
         python engine/scope.py --show
"""
import ipaddress
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psycopg  # noqa: E402

DATABASE_URL = os.environ["DATABASE_URL"]

try:  # eTLD+1 correct (co.uk...) via snapshot BUNDLÉ, aucune requête réseau.
    import tldextract  # noqa: E402
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
except Exception:  # pragma: no cover - SDK absent : on n'invente aucune racine (F4)
    _EXTRACT = None


def _sans_port(host):
    """Retire le PORT sans casser une IPv6. `[::1]:8080` -> `::1` ; `h:8080` -> `h` (si le
    suffixe est numérique) ; un IPv6 nu (plusieurs ':') n'est jamais coupé."""
    h = (host or "").strip().lower().rstrip(".")
    if h.startswith("[") and "]" in h:            # IPv6 entre crochets, port optionnel après ]
        return h[1:h.index("]")]
    if h.count(":") == 1:                          # host:port (un seul ':')
        gauche, _, droite = h.rpartition(":")
        if droite.isdigit():
            return gauche
    return h


def _est_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def registered_domain(host):
    """Racine SÛRE d'un host, ou None si on ne peut pas en dériver une (host alors EXCLU).
    Ordre (F2) : (a) retirer le port ; (b) IP littérale -> la racine EST l'IP entière ;
    (c) sinon eTLD+1 via tldextract. GARDE-FOU (F3) : un suffixe public seul (co.uk, fr…)
    n'est jamais une racine (mettrait un TLD entier dans le périmètre) -> None."""
    if not host or not host.strip():
        return None
    h = _sans_port(host)
    if _est_ip(h):                                 # (b) IPv4/IPv6 -> IP complète, jamais découpée
        return h
    if _EXTRACT is None:                            # (F4) repli sans tldextract : ne devine pas un domaine
        return None
    e = _EXTRACT(h)                                 # (c) eTLD+1
    if not e.domain or not e.suffix:               # (F3) suffixe public seul / pas de domaine enregistrable
        return None
    return e.registered_domain                     # domaine.suffixe


def deriver_roots(hosts):
    """Ensemble des racines sûres. Un host sans racine sûre (IP tronquée, suffixe public,
    garbage) est EXCLU et journalisé (F4) plutôt que deviné : périmètre trop étroit >
    périmètre trop large."""
    roots, exclus = set(), []
    for h in hosts:
        if not h or not h.strip():
            continue
        r = registered_domain(h)
        if r is None:
            exclus.append(h.strip())
        else:
            roots.add(r)
    if exclus:
        uniq = sorted(set(exclus))
        sys.stderr.write("[scope] %d host(s) SANS racine sûre -> EXCLUS des racines "
                         "(visibles avec INCLURE_HORS_SCOPE=1) : %s%s\n"
                         % (len(uniq), ", ".join(uniq[:15]), " …" if len(uniq) > 15 else ""))
    return sorted(roots)


def _assurer_table(cur):
    cur.execute("CREATE TABLE IF NOT EXISTS scope_roots (root TEXT PRIMARY KEY)")


def enregistrer_roots(roots):
    """Remplace le scope courant par `roots` (le scope = la liste lancée maintenant)."""
    with psycopg.connect(DATABASE_URL) as c, c.cursor() as cur:
        _assurer_table(cur)
        cur.execute("DELETE FROM scope_roots")
        cur.executemany("INSERT INTO scope_roots(root) VALUES (%s) ON CONFLICT DO NOTHING",
                        [(r,) for r in roots])
        c.commit()
    return len(roots)


def charger_roots():
    with psycopg.connect(DATABASE_URL) as c, c.cursor() as cur:
        _assurer_table(cur)
        cur.execute("SELECT root FROM scope_roots")
        return {r[0] for r in cur.fetchall()}


def hors_scope(host, roots):
    """True si le host est hors du scope dérivé. Fail-open : scope vide -> rien exclu."""
    if not roots:
        return False
    return registered_domain(host) not in roots


def _hosts_de_la_base():
    """La liste RÉELLEMENT lancée = les hosts distincts déjà en base (targets)."""
    with psycopg.connect(DATABASE_URL) as c, c.cursor() as cur:
        cur.execute("SELECT DISTINCT host FROM targets WHERE host IS NOT NULL")
        return [r[0] for r in cur.fetchall()]


def main(argv):
    hosts = None
    if "--file" in argv:
        f = argv[argv.index("--file") + 1]
        hosts = [l.strip() for l in Path(f).read_text().splitlines() if l.strip()]
    elif "--from-db" in argv:
        hosts = _hosts_de_la_base()
    if hosts is not None:
        roots = deriver_roots(hosts)
        n = enregistrer_roots(roots)
        print("SCOPE_ROOTS dérivé de %d hosts -> %d racines persistées :" % (len(hosts), n))
        for r in roots:
            print("   " + r)
        return 0
    if "--show" in argv:
        for r in sorted(charger_roots()):
            print(r)
        return 0
    print("usage: python engine/scope.py --file targets.txt | --from-db | --show")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
