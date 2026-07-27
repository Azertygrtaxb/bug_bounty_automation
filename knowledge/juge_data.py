"""Étape 2 — RÈGLE DE DÉCISION du juge sémantique per-id (corps DATA).

Séparation stricte EXTRACTION / DÉCISION :
  - le JUGE (LLM, sous-agent FRAIS et AVEUGLE, hors de ce module) EXTRAIT 4 faits
    observables d'UN corps data ;
  - ce module ne contient AUCUNE IA : il DÉCIDE, en code déterministe, à partir des
    faits extraits, et gère le type de corps + la détection de leurre.

Le juge FLAGGE, l'humain confirme. Jamais de conclusion « IDOR », jamais de jugement
d'exploitabilité, jamais de soumission.

Faits extraits par le juge (valeurs FERMÉES) :
  pii_enregistrement     : {oui | non}
  instance_vs_generique  : {instance | générique}
  marqueur_propriete     : {oui | non}
  sensibilite            : {oui | non}
"""

# --- Types de corps binaires : NE PAS donner au LLM ----------------------------
# Un document téléchargeable par id en non-auth est INTRINSÈQUEMENT escaladé (humain).
# Extraction texte (pdftotext...) = capacité future, pas ici. Set éditable.
TYPES_BINAIRES = {"application/pdf", "application/octet-stream", "application/zip",
                  "application/x-zip-compressed"}


def type_corps_binaire(content_type):
    ct = (content_type or "").split(";")[0].strip().lower()
    if not ct:
        return False
    if ct in TYPES_BINAIRES:
        return True
    return ct.startswith(("application/pdf", "application/zip", "application/octet",
                          "application/x-"))


def decider(faits):
    """DÉCISION déterministe à partir des 4 faits extraits par le juge (corps texte).
    Renvoie {verdict, confiance, flags, faits}. Seuils = les conditions booléennes
    ci-dessous, éditables.

      OWNED/SENSIBLE  (candidat FORT, flag humain, priorité haute) :
          (PII=oui ET INSTANCE=instance ET PROPRIETE=oui)  OU  SENSIBILITE=oui
      PUBLIC          (déprioriser, comme résidu B) :
          INSTANCE=générique ET PII=non ET SENSIBILITE=non
      UNCERTAIN       (mélange/contradiction) -> humain.
    """
    pii       = faits.get("pii_enregistrement") == "oui"
    instance  = faits.get("instance_vs_generique") == "instance"
    generique = faits.get("instance_vs_generique") == "générique"
    propriete = faits.get("marqueur_propriete") == "oui"
    sensible  = faits.get("sensibilite") == "oui"

    owned  = (pii and instance and propriete) or sensible
    public = generique and (not pii) and (not sensible)

    flags = []
    if owned:
        verdict = "OWNED_SENSIBLE"
        confiance = "haute" if (pii and instance and propriete and sensible) else "moyenne"
        # HUMAIN-DANS-LA-BOUCLE + HONEYPOT (§7) : tout résultat fort passe la revue
        # leurre (data sensible « trop belle » = à vérifier), jamais d'auto-conclusion.
        flags += ["flag_humain", "verifier_leurre"]
    elif public:
        verdict, confiance = "PUBLIC", "haute"
    else:
        verdict, confiance = "UNCERTAIN", "basse"
        flags.append("flag_humain")

    return {"verdict": verdict, "confiance": confiance, "flags": flags, "faits": faits}


def decider_binaire(content_type):
    """Corps binaire (pdf/zip/octet-stream) : NON lu par le LLM. Un document
    téléchargeable par id en non-auth est intrinsèquement escaladé -> humain."""
    return {
        "verdict": "OWNED_SENSIBLE",
        "confiance": "moyenne",
        "flags": ["document_binaire_rendu_par_id", "binaire_non_lu_LLM",
                  "flag_humain", "verifier_leurre"],
        "faits": {"content_type": content_type,
                  "note": "binaire non extrait (pdftotext = capacite future)"},
    }
