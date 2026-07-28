-- VUE LEADS PERSISTÉE — source de vérité curée (1b scope + 1c collapse), régénérée
-- à chaque re-score par la tâche rebuild_leads. `targets` garde le détail par
-- endpoint ; `leads` est la vue collapse (un représentant par (host, pattern)).
CREATE TABLE IF NOT EXISTS leads (
    host               TEXT        NOT NULL,
    pattern            TEXT        NOT NULL,   -- lead_pattern normalisé ({id}/{annee}/{*})
    url_representative  TEXT,                  -- URL du membre au score max du groupe
    score              INTEGER,
    raisons            TEXT[],                 -- score_raisons du représentant
    nb                 INTEGER,                -- taille du groupe collapse (1c)
    http_status        INTEGER,
    tech               TEXT[],
    in_scope           BOOLEAN,                -- registered-domain ∈ SCOPE_ROOTS
    updated_at         TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (host, pattern)
);
CREATE INDEX IF NOT EXISTS idx_leads_score ON leads (score DESC);
