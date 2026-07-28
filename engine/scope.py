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
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psycopg  # noqa: E402

DATABASE_URL = os.environ["DATABASE_URL"]

try:  # eTLD+1 correct (co.uk...) si dispo ; sinon repli 2 derniers labels
    import tldextract  # noqa: E402
    _EXTRACT = tldextract.TLDExtract(suffix_list_urls=())  # offline (snapshot bundlé)

    def registered_domain(host):
        e = _EXTRACT((host or "").strip().lower())
        return e.registered_domain or (host or "").strip().lower()
except Exception:  # pragma: no cover - repli sans dépendance
    def registered_domain(host):
        labels = (host or "").strip().lower().rstrip(".").split(".")
        return ".".join(labels[-2:]) if len(labels) >= 2 else (host or "").strip().lower()


def deriver_roots(hosts):
    return sorted({registered_domain(h) for h in hosts if h and h.strip()})


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


def main(argv):
    if "--file" in argv:
        f = argv[argv.index("--file") + 1]
        hosts = [l.strip() for l in Path(f).read_text().splitlines() if l.strip()]
        roots = deriver_roots(hosts)
        n = enregistrer_roots(roots)
        print("SCOPE_ROOTS dérivé de %d hosts -> %d registered-domains persistés :" % (len(hosts), n))
        for r in roots:
            print("   " + r)
        return 0
    if "--show" in argv:
        for r in sorted(charger_roots()):
            print(r)
        return 0
    print("usage: python engine/scope.py --file targets.txt | --show")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
