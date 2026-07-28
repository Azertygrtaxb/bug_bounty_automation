"""VUE LEADS — leads propres et lisibles (export CSV / rapport / dashboard).

N'AGIT PAS sur le scoring : la base garde le détail complet. Cette vue applique, à la
LECTURE :
  1b — EXCLUT les leads hors-cible (rebond sur un domaine hors périmètre in-scope,
       config §14) sauf INCLURE_HORS_CIBLE.
  1c — COLLAPSE GÉNÉRALISÉ : un même PATTERN normalisé (id/UUID/opaque -> {id}, année ->
       {annee}) + les frères qui ne varient QUE sur UN segment (position quelconque) OU
       QUE sur des valeurs de query (>= COLLAPSE_PREFIXE_MIN) => slot replié en {*}, UN
       représentant (score max) + compteur `nb`.

Le pattern normalisé est stocké (tags.lead_pattern) pour que le dashboard groupe pareil.

La vue est PERSISTÉE dans la table `leads` (source de vérité) : construire() calcule,
persister() remplace tout (garde-fou : jamais sur liste vide), lire() relit sans
recalcul. La tâche Celery rebuild_leads (engine/scoring/score.py) la régénère après
chaque score_targets. targets reste le détail par endpoint ; leads = la vue curée.

Le STATUT de triage humain vit dans `leads_statut` (JAMAIS truncatée) ; lire() le joint
(défaut 'a_voir'). Un quota par host (MAX_LEADS_PAR_HOST, §14) s'applique à la LECTURE :
au plus N lignes/host + une ligne de repli « +M autres » — on déprioritise, on ne
supprime jamais (§0.4).

Usage :  python engine/leads.py [seuil] [--rebuild] [--csv fichier]
         python engine/leads.py --statut <host> <pattern> <statut> [note]
    --rebuild : recalcule (1b+1c) et remplace la table leads (sinon lit la table).
"""
import os
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psycopg  # noqa: E402

from engine import scope  # noqa: E402
from knowledge import config, harvest  # noqa: E402
from knowledge.signaux import _ID_PARAM_KEYS, _est_annee_chemin  # noqa: E402

DATABASE_URL = os.environ["DATABASE_URL"]
_ID_KEYS = _ID_PARAM_KEYS


def _seg_token(seg):
    if not seg:
        return seg
    if _est_annee_chemin(seg):
        return "{annee}"
    sh = harvest.shape_of(seg)
    if sh and sh[0] in ("num", "uuid", "objectid", "opaque"):
        return "{id}"
    return seg


def patternize(url):
    """URL -> PATTERN normalisé (segments id -> {id}/{annee}, valeurs params-id -> {id})."""
    p = urlsplit(url)
    path = "/".join(_seg_token(s) for s in p.path.split("/"))
    parts = []
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        kl = k.lower()
        if kl in config.PARAMS_PAGINATION:      # pagination = bruit -> {*} quelle que soit la valeur
            parts.append("%s={*}" % k)
        elif v and (kl in _ID_KEYS or kl.endswith("_id") or kl == "id"):
            parts.append("%s={id}" % k)
        elif _est_annee_chemin(v):
            parts.append("%s={annee}" % k)
        elif v:
            parts.append("%s=%s" % (k, v))
        else:
            parts.append("%s=" % k)
    return path + ("?" + "&".join(parts) if parts else "")


_MARQUEURS = ("{id}", "{annee}", "{*}")


def _est_marqueur(x):
    return x in _MARQUEURS


def _split_pattern(pat):
    """PATTERN -> (segments de chemin, [(clé, valeur)] de query)."""
    path, _, query = pat.partition("?")
    segs = path.split("/")
    pairs = []
    for kv in (query.split("&") if query else []):
        k, _, v = kv.partition("=")
        pairs.append((k, v))
    return segs, pairs


def _join_pattern(segs, pairs):
    path = "/".join(segs)
    if pairs:
        return path + "?" + "&".join("%s=%s" % (k, v) for k, v in pairs)
    return path


def _famille_homogene(membres, prof):
    """B2 : tous les membres ont le même profil de signal (score + ensemble de raisons).
    Profils différents = endpoints différents = on ne fusionne pas. Profil manquant
    (None) -> considéré hétérogène par prudence."""
    if not config.COLLAPSE_EXIGE_MEME_PROFIL:
        return True
    profils = {prof.get(p) for p in membres}
    return len(profils) == 1 and None not in profils


def _collapse_freres(patterns_par_host, profil=None):
    """COLLAPSE GÉNÉRALISÉ. Deux patterns d'un même host sont FRÈRES s'ils ont le même
    nombre de segments de chemin, le même ensemble de CLÉS de query, et ne diffèrent QUE
    sur UN seul segment de chemin (position quelconque) OU QUE sur des VALEURS de query.
    >= COLLAPSE_PREFIXE_MIN frères ET profil homogène (B2) -> le slot qui varie est replié
    en {*}, on garde le représentant au score max. Jamais on ne replie un {id}/{annee}
    (c'est le signal), NI le segment juste AVANT un {id}/{annee} (B1 : c'est le TYPE
    D'OBJET, la cible BOLA). UN SEUL segment de chemin replié à la fois. Renvoie
    {(host, pattern): pattern_replié}. `profil` = {(host, pattern): (score, frozenset(raisons))}.

    Chaque pattern retient le repli dont la FAMILLE est la plus grande (>= MIN)."""
    seuil = config.COLLAPSE_PREFIXE_MIN
    profil = profil or {}
    par_host = defaultdict(list)
    for host, pat in patterns_par_host:
        par_host[host].append(pat)

    remap = {}
    for host in sorted(par_host):
        pats = sorted(dict.fromkeys(par_host[host]))       # unique, ordre déterministe
        parsed = {p: _split_pattern(p) for p in pats}
        prof = {p: profil.get((host, p)) for p in pats}    # profil local au host

        # (A) familles PATH : un seul segment (non-marqueur) remplacé par {*}, query
        # identique. genkey inclut la query complète -> frères = même query exacte.
        # B1 : on n'engendre PAS de candidat sur un segment suivi d'un {id}/{annee}.
        path_fam = defaultdict(set)
        path_folded = {}
        for p in pats:
            segs, pairs = parsed[p]
            for i, seg in enumerate(segs):
                if _est_marqueur(seg) or seg == "":
                    continue
                if (not config.REPLIER_SEGMENT_AVANT_ID and i + 1 < len(segs)
                        and segs[i + 1] in ("{id}", "{annee}")):
                    continue  # segment = TYPE D'OBJET devant un id -> intouchable (B1)
                ns = list(segs); ns[i] = "{*}"
                gk = ("P", tuple(ns), tuple(pairs))
                path_fam[gk].add(p)
                path_folded[(p, gk)] = _join_pattern(ns, pairs)

        # (B) familles QUERY : même chemin + mêmes clés + même structure id/annee/vide,
        # ne diffèrent que sur des valeurs LITTÉRALES. On replie seulement les clés dont
        # la valeur VARIE dans la famille (les littéraux constants restent tels quels).
        q_fam = defaultdict(set)
        for p in pats:
            segs, pairs = parsed[p]
            if not pairs:
                continue
            loose = ("Q", tuple(segs),
                     tuple((k, v if (_est_marqueur(v) or v == "") else "\x00") for k, v in pairs))
            q_fam[loose].add(p)

        best = {}  # pattern -> (taille_famille, pattern_replié)

        for gk, membres in path_fam.items():
            if len(membres) < seuil or not _famille_homogene(membres, prof):
                continue
            for p in membres:
                cand = (len(membres), path_folded[(p, gk)])
                if cand[0] > best.get(p, (0, None))[0]:
                    best[p] = cand

        for loose, membres in q_fam.items():
            if len(membres) < seuil or not _famille_homogene(membres, prof):
                continue
            segs = list(loose[1])
            nb_cles = len(loose[2])
            varie = [set() for _ in range(nb_cles)]
            for p in membres:
                for idx, (k, v) in enumerate(parsed[p][1]):
                    if not (_est_marqueur(v) or v == ""):
                        varie[idx].add(v)
            for p in membres:
                new_pairs = []
                for idx, (k, v) in enumerate(parsed[p][1]):
                    if not (_est_marqueur(v) or v == "") and len(varie[idx]) > 1:
                        new_pairs.append((k, "{*}"))
                    else:
                        new_pairs.append((k, v))
                cand = (len(membres), _join_pattern(segs, new_pairs))
                if cand[0] > best.get(p, (0, None))[0]:
                    best[p] = cand

        for p, (_, folded) in best.items():
            remap[(host, p)] = folded
    return remap


def _assurer_table(cur):
    """CREATE TABLE IF NOT EXISTS (idempotent, aligné sur db/006 + db/007). Crée AUSSI
    l'index et la table de statut : une base montée par le code seul est complète."""
    cur.execute(
        "CREATE TABLE IF NOT EXISTS leads ("
        " host TEXT NOT NULL, pattern TEXT NOT NULL, url_representative TEXT,"
        " score INTEGER, raisons TEXT[], nb INTEGER, http_status INTEGER,"
        " tech TEXT[], in_scope BOOLEAN, premiere_vue TIMESTAMPTZ,"
        " updated_at TIMESTAMPTZ DEFAULT now(), PRIMARY KEY (host, pattern))")
    cur.execute("ALTER TABLE leads ADD COLUMN IF NOT EXISTS premiere_vue TIMESTAMPTZ")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_leads_score ON leads (score DESC)")
    cur.execute(
        "CREATE TABLE IF NOT EXISTS leads_statut ("
        " host TEXT NOT NULL, pattern TEXT NOT NULL, statut TEXT DEFAULT 'a_voir',"
        " note TEXT, ancre_url TEXT, orphelin BOOLEAN DEFAULT false,"
        " updated_at TIMESTAMPTZ DEFAULT now(), PRIMARY KEY (host, pattern))")
    cur.execute("ALTER TABLE leads_statut ADD COLUMN IF NOT EXISTS orphelin BOOLEAN DEFAULT false")
    cur.execute("ALTER TABLE leads_statut ADD COLUMN IF NOT EXISTS ancre_url TEXT")


def construire(seuil=1):
    """Calcule les leads curés (1b scope + 1c collapse). Renvoie (lignes, stats, remap).
    Chaque ligne = {host, pattern, url_representative, score, raisons, nb, http_status,
    tech, in_scope} (le représentant = le membre au score MAX du groupe). `remap` =
    {(host, pattern_avant): pattern_apres} pour migrer leads_statut. Écrit aussi
    tags.lead_pattern sur targets (groupement dashboard). N'ÉCRIT PAS dans `leads` :
    c'est persister() qui le fait (séparation calcul / écriture)."""
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, host, url, score, COALESCE(score_raisons,'{}'), "
                        "http_status, COALESCE(tech,'{}'), COALESCE(tags,'{}'), cree_le "
                        "FROM targets WHERE score >= %s", (seuil,))
            rows = cur.fetchall()

            brut = len(rows)
            # 1b — exclusion HORS-SCOPE : registered-domain ∉ SCOPE_ROOTS dérivé de la
            # liste lancée (OU marque hors_cible si présente). Scope vide -> fail-open.
            roots = scope.charger_roots()
            gardes, exclus_hc = [], 0
            for rid, host, url, score, raisons, http_status, tech, tags, cree_le in rows:
                marque = "hors_cible_de_lancement" in ",".join(raisons)
                dehors = scope.hors_scope(host, roots) or marque
                if not config.INCLURE_HORS_SCOPE and dehors:
                    exclus_hc += 1
                    continue
                gardes.append({"id": rid, "host": host, "url": url, "score": score,
                               "raisons": list(raisons or []), "http_status": http_status,
                               "tech": list(tech or []), "tags": tags,
                               "in_scope": not dehors, "cree_le": cree_le})
            apres_1b = len(gardes)

            # 1c — patternize + stockage tags.lead_pattern
            for g in gardes:
                pat = patternize(g["url"])
                g["pattern"] = pat
                if (g["tags"] or {}).get("lead_pattern") != pat:
                    cur.execute("UPDATE targets SET tags = jsonb_set(COALESCE(tags,'{}'::jsonb), "
                                "'{lead_pattern}', to_jsonb(%s::text)) WHERE id = %s", (pat, g["id"]))
            # Profil de signal par (host, pattern) = celui du membre au score MAX (base de
            # la garde d'homogénéité B2). raisons en frozenset (ordre non signifiant).
            profil = {}
            for g in gardes:
                key = (g["host"], g["pattern"])
                p = (g["score"], frozenset(g["raisons"]))
                cur_prof = profil.get(key)
                if cur_prof is None or g["score"] > cur_prof[0]:
                    profil[key] = p
            # collapse généralisé (B1 segment-avant-id + B2 homogénéité de profil)
            remap = _collapse_freres({(g["host"], g["pattern"]) for g in gardes}, profil)
            groupes = {}  # (host, pattern_final) -> {nb, score_max, representant, premiere_vue}
            for g in gardes:
                pat = remap.get((g["host"], g["pattern"]), g["pattern"])
                key = (g["host"], pat)
                grp = groupes.setdefault(key, {"nb": 0, "score": -1, "rep": None, "premiere_vue": None})
                grp["nb"] += 1
                if g["score"] > grp["score"]:
                    grp["score"] = g["score"]; grp["rep"] = g
                cv = g["cree_le"]
                if cv is not None and (grp["premiere_vue"] is None or cv < grp["premiere_vue"]):
                    grp["premiere_vue"] = cv    # R1 : MIN(cree_le) sur les membres = première-vue
        conn.commit()

    lignes = []
    for (host, pat), grp in groupes.items():
        rep = grp["rep"]
        lignes.append({"host": host, "pattern": pat, "url_representative": rep["url"],
                       "score": grp["score"], "raisons": rep["raisons"], "nb": grp["nb"],
                       "http_status": rep["http_status"], "tech": rep["tech"],
                       "in_scope": rep["in_scope"], "premiere_vue": grp["premiere_vue"]})
    lignes.sort(key=lambda x: (x["score"], x["nb"]), reverse=True)
    # remap {(host, pattern_avant_collapse): pattern_apres} pour migrer les statuts.
    return lignes, {"brut": brut, "apres_1b": apres_1b, "exclus_hors_cible": exclus_hc,
                    "apres_1c": len(lignes)}, remap


def _rang_statut(statut):
    """Position dans ORDRE_STATUT (plus grand = plus avancé). Inconnu -> -1."""
    o = config.ORDRE_STATUT
    return o.index(statut) if statut in o else -1


def _migrer_statut(cur, remap):
    """A2 — migre leads_statut à travers le remap {(host, avant): apres} AVANT de
    réécrire `leads`. Ne truncate JAMAIS la table : seules les clés RENOMMÉES bougent.
    Collision (plusieurs sources -> même cible, ou cible déjà statutée) : on garde le
    statut le PLUS AVANCÉ (ORDRE_STATUT) et on CONCATÈNE les notes (jamais perdre une
    note humaine)."""
    renames = {(h, a): (h, ap) for (h, a), ap in remap.items() if a != ap}
    if not renames:
        return 0
    cur.execute("SELECT host, pattern, statut, note FROM leads_statut")
    existing = {(h, p): (s, n) for h, p, s, n in cur.fetchall()}
    sources = [k for k in renames if k in existing]
    if not sources:
        return 0
    # agrège vers chaque clé cible (en incluant un statut déjà présent sur la cible)
    cibles = {}
    for src in sources:
        dst = renames[src]
        agg = cibles.setdefault(dst, {"statut": "a_voir", "notes": []})
        s, n = existing[src]
        if _rang_statut(s) >= _rang_statut(agg["statut"]):
            agg["statut"] = s
        if n:
            agg["notes"].append(n)
    for dst, agg in cibles.items():
        if dst in existing:
            s, n = existing[dst]
            if _rang_statut(s) >= _rang_statut(agg["statut"]):
                agg["statut"] = s
            if n and n not in agg["notes"]:
                agg["notes"].append(n)
    # applique : supprime les sources renommées, upsert les cibles fusionnées
    for h, p in sources:
        cur.execute("DELETE FROM leads_statut WHERE host = %s AND pattern = %s", (h, p))
    for (h, p), agg in cibles.items():
        note = " | ".join(agg["notes"]) if agg["notes"] else None
        cur.execute(
            "INSERT INTO leads_statut (host, pattern, statut, note, orphelin, updated_at) "
            "VALUES (%s, %s, %s, %s, false, now()) ON CONFLICT (host, pattern) DO UPDATE "
            "SET statut = EXCLUDED.statut, note = EXCLUDED.note, orphelin = false, "
            "updated_at = now()", (h, p, agg["statut"], note))
    return len(sources)


def _marquer_orphelins(cur):
    """A3 — un statut dont la clé n'existe plus dans `leads` = ORPHELIN. On le MARQUE
    (jamais supprimé) ; ceux qui réapparaissent repassent orphelin=false."""
    cur.execute("UPDATE leads_statut s SET orphelin = NOT EXISTS "
                "(SELECT 1 FROM leads l WHERE l.host = s.host AND l.pattern = s.pattern)")


def _reconcilier_ancres(cur):
    """LOT 0 (0.3) — réconciliation par ANCRE, sens replié->dé-replié que remap ne couvre
    pas. Pour chaque statut dont la clé (host,pattern) n'existe plus dans `leads` mais dont
    l'ancre_url existe encore dans `targets`, on lit tags.lead_pattern (écrit par construire)
    de cette URL et on DÉPLACE le statut dessus. Collision -> ORDRE_STATUT + notes
    concaténées. Reste orphelin seulement si l'ancre a disparu de `targets`. À appeler APRÈS
    la réécriture de `leads`, AVANT _marquer_orphelins."""
    cur.execute("SELECT s.host, s.pattern, s.ancre_url, s.statut, s.note FROM leads_statut s "
                "WHERE s.ancre_url IS NOT NULL AND NOT EXISTS "
                "(SELECT 1 FROM leads l WHERE l.host = s.host AND l.pattern = s.pattern)")
    perdus = cur.fetchall()
    deplaces = 0
    for old_host, old_pat, ancre, statut, note in perdus:
        cur.execute("SELECT host, tags->>'lead_pattern' FROM targets WHERE url = %s LIMIT 1", (ancre,))
        row = cur.fetchone()
        if not row or not row[1]:
            continue  # ancre disparue de targets -> reste orphelin
        new_host, new_pat = row[0], row[1]
        if (new_host, new_pat) == (old_host, old_pat):
            continue
        cur.execute("SELECT 1 FROM leads WHERE host = %s AND pattern = %s", (new_host, new_pat))
        if not cur.fetchone():
            continue  # la cible n'est pas un lead courant -> reste orphelin
        cur.execute("SELECT statut, note FROM leads_statut WHERE host = %s AND pattern = %s",
                    (new_host, new_pat))
        ex = cur.fetchone()
        best, notes = statut, ([note] if note else [])
        if ex:
            if _rang_statut(ex[0]) >= _rang_statut(best):
                best = ex[0]
            if ex[1] and ex[1] not in notes:
                notes.append(ex[1])
        merged = " | ".join(notes) if notes else None
        cur.execute(
            "INSERT INTO leads_statut (host, pattern, statut, note, ancre_url, orphelin, updated_at) "
            "VALUES (%s, %s, %s, %s, %s, false, now()) ON CONFLICT (host, pattern) DO UPDATE "
            "SET statut = EXCLUDED.statut, note = EXCLUDED.note, "
            "ancre_url = COALESCE(leads_statut.ancre_url, EXCLUDED.ancre_url), "
            "orphelin = false, updated_at = now()", (new_host, new_pat, best, merged, ancre))
        cur.execute("DELETE FROM leads_statut WHERE host = %s AND pattern = %s", (old_host, old_pat))
        deplaces += 1
    return deplaces


def persister(lignes, remap=None):
    """Remplace TOUT le contenu de `leads` par `lignes`. GARDE-FOU (A4) : liste VIDE ->
    on NE truncate PAS (un rebuild raté ne doit jamais vider le board), on avertit et on
    sort. Ordre : _migrer_statut(remap) AVANT réécriture ; _reconcilier_ancres +
    _marquer_orphelins APRÈS. `leads_statut` n'est jamais truncatée."""
    if not lignes:
        sys.stderr.write("[leads] AVERTISSEMENT : rebuild VIDE -> table `leads` NON "
                         "touchée (garde-fou A4).\n")
        return 0
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            _assurer_table(cur)
            if remap:
                _migrer_statut(cur, remap)               # repli -> replié (patterns bruts)
            cur.execute("TRUNCATE leads")
            cur.executemany(
                "INSERT INTO leads (host, pattern, url_representative, score, raisons, "
                "nb, http_status, tech, in_scope, premiere_vue, updated_at) VALUES "
                "(%(host)s, %(pattern)s, %(url_representative)s, %(score)s, %(raisons)s, "
                "%(nb)s, %(http_status)s, %(tech)s, %(in_scope)s, %(premiere_vue)s, now())", lignes)
            _reconcilier_ancres(cur)                     # replié -> dé-replié (via ancre_url)
            _marquer_orphelins(cur)
        conn.commit()
    return len(lignes)


def lister_orphelins():
    """Statuts dont la clé n'existe plus dans `leads` (travail humain à re-router)."""
    with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
        cur.execute("SELECT host, pattern, statut, note, ancre_url FROM leads_statut "
                    "WHERE orphelin ORDER BY host, pattern")
        return [{"host": h, "pattern": p, "statut": s, "note": n, "ancre_url": a}
                for h, p, s, n, a in cur.fetchall()]


def marquer(host, pattern, statut, note=None, ancre_url=None):
    """UPSERT du statut de triage HUMAIN. Refuse un statut hors STATUTS_LEAD. note=None
    conserve la note existante. ancre_url manquante -> remplie avec le url_representative
    du lead visé (l'URL réelle que l'humain regardait). AUCUN DDL : compatible avec un
    rôle postgres SELECT + INSERT/UPDATE sur leads_statut (le board tourne ainsi)."""
    if statut not in config.STATUTS_LEAD:
        raise ValueError("statut %r invalide (attendus: %s)" % (statut, config.STATUTS_LEAD))
    with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
        if ancre_url is None:
            cur.execute("SELECT url_representative FROM leads WHERE host = %s AND pattern = %s",
                        (host, pattern))
            row = cur.fetchone()
            ancre_url = row[0] if row else None
        cur.execute(
            "INSERT INTO leads_statut (host, pattern, statut, note, ancre_url, updated_at) "
            "VALUES (%s, %s, %s, %s, %s, now()) ON CONFLICT (host, pattern) DO UPDATE SET "
            "statut = EXCLUDED.statut, note = COALESCE(EXCLUDED.note, leads_statut.note), "
            "ancre_url = COALESCE(EXCLUDED.ancre_url, leads_statut.ancre_url), updated_at = now()",
            (host, pattern, statut, note, ancre_url))
        conn.commit()
    return True


def _appliquer_quota(rows):
    """Quota de diversité par host (§14 MAX_LEADS_PAR_HOST) À LA LECTURE : au plus N
    lignes/host (mieux scorées) + UNE ligne de repli « +M autres leads » (score = max du
    reste) pour ne rien faire disparaître. 0 = illimité."""
    mx = config.MAX_LEADS_PAR_HOST
    if not mx or mx <= 0:
        return rows
    par_host = defaultdict(list)
    for r in rows:
        par_host[r["host"]].append(r)
    out = []
    for host, lst in par_host.items():
        lst.sort(key=lambda x: (x["score"], x["nb"] or 0), reverse=True)
        out.extend(lst[:mx])
        reste = lst[mx:]
        if reste:
            out.append({"host": host, "pattern": "+%d autres leads" % len(reste),
                        "url_representative": None, "score": reste[0]["score"],
                        "raisons": ["quota_host(%d masqués)" % len(reste)], "nb": None,
                        "http_status": None, "tech": [], "in_scope": True,
                        "premiere_vue": None, "statut": "-", "note": None, "type": "repli"})
    out.sort(key=lambda x: (x["score"], x["nb"] or 0), reverse=True)
    return out


def lire(seuil=1, quota=True):
    """Lit `leads` (source de vérité) + LEFT JOIN leads_statut (statut/​note, défaut
    'a_voir') — AUCUN recalcul, AUCUN DDL (C1 : lecture 100% read-only, compatible user
    postgres restreint). `quota=False` -> liste brute sans repli (C2, pour API/export
    machine). Chaque ligne porte `type` = 'lead' | 'repli' (C3) + `premiere_vue` (R1)."""
    with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
        cur.execute("SELECT l.host, l.pattern, l.url_representative, l.score, l.raisons, "
                    "l.nb, l.http_status, l.tech, l.in_scope, l.premiere_vue, "
                    "COALESCE(s.statut, %s) AS statut, s.note "
                    "FROM leads l LEFT JOIN leads_statut s "
                    "  ON s.host = l.host AND s.pattern = l.pattern "
                    "WHERE l.score >= %s ORDER BY l.score DESC, l.nb DESC",
                    (config.STATUT_DEFAUT, seuil))
        cols = [d[0] for d in cur.description]
        rows = [dict(zip(cols, r), type="lead") for r in cur.fetchall()]
    return _appliquer_quota(rows) if quota else rows


def detail(host, pattern):
    """R2 — détail LECTURE SEULE d'un lead (replié ou non) pour le panneau latéral :
    les MEMBRES réels du groupe (url/score/http_status), les raisons + response_headers du
    représentant, et un EXTRAIT borné de body_text. Aucun DDL. Regroupe par
    tags.lead_pattern = `pattern` sur le host (ce que construire a écrit)."""
    with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT url, score, http_status, COALESCE(score_raisons,'{}'), "
            "response_headers, body_text FROM targets "
            "WHERE host = %s AND tags->>'lead_pattern' = %s ORDER BY score DESC, url",
            (host, pattern))
        rows = cur.fetchall()
    membres = [{"url": u, "score": sc, "http_status": st} for (u, sc, st, _, _, _) in rows]
    rep = rows[0] if rows else None
    extrait = None
    if rep and rep[5]:
        extrait = rep[5][:config.EXTRAIT_CORPS_MAX]
    return {
        "host": host, "pattern": pattern, "nb": len(membres),
        "representant": rep[0] if rep else None,
        "raisons": list(rep[3]) if rep else [],
        "response_headers": rep[4] if rep else None,
        "body_extrait": extrait,
        "body_tronque": bool(rep and rep[5] and len(rep[5]) > config.EXTRAIT_CORPS_MAX),
        "membres": membres,
    }


def main(argv):
    if "--statut" in argv:  # python engine/leads.py --statut <host> <pattern> <statut> [note]
        i = argv.index("--statut")
        host, pattern, statut = argv[i + 1], argv[i + 2], argv[i + 3]
        note = argv[i + 4] if len(argv) > i + 4 and not argv[i + 4].startswith("--") else None
        marquer(host, pattern, statut, note)
        print("statut '%s' posé sur %s %s" % (statut, host, pattern))
        return 0

    if "--orphelins" in argv:  # statuts dont la clé n'existe plus dans `leads`
        orph = lister_orphelins()
        print("=== %d STATUT(S) ORPHELIN(S) (jamais supprimés — à re-router) ===" % len(orph))
        for o in orph:
            print("  [%s] %s %s  note=%s" % (o["statut"], o["host"], o["pattern"], o["note"]))
        return 0

    seuil = next((int(a) for a in argv if a.isdigit()), 1)
    if "--rebuild" in argv:  # recalcule (1b+1c) et remplace la table
        lignes, st, remap = construire(seuil)
        n = persister(lignes, remap)
        print("=== REBUILD leads (seuil>=%d) : brut %d -> 1b %d (hors-scope exclus %d) "
              "-> 1c %d => %d persistés ===" % (seuil, st["brut"], st["apres_1b"],
                                                st["exclus_hors_cible"], st["apres_1c"], n))

    # AFFICHAGE + EXPORT : lecture depuis la table `leads` (+ statut + quota), pas de recalcul.
    lignes = lire(seuil)
    print("%-5s %-4s %-9s %-6s %-38s %s" % ("score", "nb", "statut", "type", "host", "pattern"))
    for r in lignes[:40]:
        nb = str(r["nb"]) if r["nb"] is not None else "-"
        print("%-5d %-4s %-9s %-6s %-38s %s" % (r["score"], nb, (r.get("statut") or "-")[:9],
                                                r.get("type", "lead"), r["host"][:38],
                                                r["pattern"][:70]))
    if "--csv" in argv:
        chemin = argv[argv.index("--csv") + 1]
        import csv as _csv
        with open(chemin, "w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh)
            w.writerow(["type", "score", "nb", "statut", "host", "pattern",
                        "url_representative", "http_status", "in_scope", "note", "raisons"])
            for r in lignes:
                w.writerow([r.get("type", "lead"), r["score"], r["nb"], r.get("statut"),
                            r["host"], r["pattern"], r["url_representative"],
                            r["http_status"], r["in_scope"], r.get("note"),
                            ",".join(r["raisons"] or [])])
        print("CSV (depuis la table leads) -> %s (%d lignes)" % (chemin, len(lignes)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
