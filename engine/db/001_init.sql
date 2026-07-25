-- Schéma initial du pipeline de reconnaissance.
-- Deux tables seulement : la surface découverte (targets) et la file (jobs).

CREATE TABLE IF NOT EXISTS targets (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    url           TEXT NOT NULL,
    host          TEXT,
    http_status   INT,
    tech          TEXT[],
    tags          JSONB,
    score         INT DEFAULT 0,
    score_raisons TEXT[],
    hash_dedup    TEXT UNIQUE,
    statut_host   TEXT DEFAULT 'en_cours',
    cree_le       TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS jobs (
    id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    type     TEXT,
    payload  JSONB,
    statut   TEXT DEFAULT 'pending',
    cree_le  TIMESTAMPTZ DEFAULT now(),
    maj_le   TIMESTAMPTZ
);
