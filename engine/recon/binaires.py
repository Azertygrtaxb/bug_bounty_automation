"""Garde-fou binaires ProjectDiscovery (httpx / katana / subfinder).

Mode d'échec RÉEL (une nuit de crawl à vide) : le SDK python `httpx` (dépendance d'anthropic)
dépose son script console de ~213 octets au même chemin que le binaire ProjectDiscovery de
54 Mo. Le code appelle "httpx" par son nom -> tombe sur le script Python -> live_hosts:0 pour
TOUS les hosts, sans aucune erreur visible. Ici on refuse de tourner dans cet état.

Stdlib uniquement : importable au BUILD (aucune variable d'environnement requise)."""
import os
import shutil
import subprocess
import sys

BINAIRES_PD = ("httpx", "katana", "subfinder")
# Le vrai binaire pèse des dizaines de Mo ; le script console pip ~213 o. 1 Mo tranche net.
TAILLE_MIN_PD = int(os.environ.get("TAILLE_MIN_PD", "1000000"))


def verifier():
    """Renvoie (ok:bool, details:dict nom->message). Ne lève pas."""
    details, ok = {}, True
    for nom in BINAIRES_PD:
        chemin = shutil.which(nom)
        if not chemin:
            details[nom] = "INTROUVABLE dans le PATH"
            ok = False
            continue
        taille = os.path.getsize(chemin)
        if taille < TAILLE_MIN_PD:
            details[nom] = ("SUSPECT %s = %d o (< %d) — un script Python MASQUE le binaire "
                            "ProjectDiscovery" % (chemin, taille, TAILLE_MIN_PD))
            ok = False
            continue
        try:
            out = subprocess.run([chemin, "-version"], capture_output=True, timeout=15)
            txt = (out.stdout + out.stderr).decode("utf-8", "replace").lower()
        except Exception as e:  # noqa: BLE001
            details[nom] = "-version a échoué (%s)" % e
            ok = False
            continue
        marque = "projectdiscovery" in txt
        details[nom] = "OK %s (%.1f Mo%s)" % (chemin, taille / 1e6,
                                              ", projectdiscovery" if marque else "")
    return ok, details


_VERIFIE = None


def exiger():
    """A1.3 — lève RuntimeError si un binaire est faux (mémoïsé : une vérif par process)."""
    global _VERIFIE
    if _VERIFIE is True:
        return
    ok, details = verifier()
    if not ok:
        mauvais = "; ".join("%s -> %s" % (k, v) for k, v in details.items()
                            if not v.startswith("OK"))
        raise RuntimeError("binaires ProjectDiscovery INVALIDES (crawl à vide muet évité) : "
                           + mauvais)
    _VERIFIE = True


def main(argv):
    ok, details = verifier()
    for k, v in details.items():
        print("  %-9s %s" % (k, v))
    if not ok:
        sys.stderr.write("[binaires] REFUS : un binaire ProjectDiscovery est invalide "
                         "(voir ci-dessus). Le crawl renverrait live_hosts:0 en silence.\n")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
