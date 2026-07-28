-- STATUT DE TRIAGE HUMAIN, découplé de la vue calculée `leads`.
-- `leads` est TRUNCATE+INSERT à chaque rebuild_leads (donnée CALCULÉE) ; le statut
-- posé par un humain (donnée SAISIE) vit ici et n'est JAMAIS truncaté par le pipeline.
-- lire() fait un LEFT JOIN : un lead sans statut vaut 'a_voir' (défaut §14).
CREATE TABLE IF NOT EXISTS leads_statut (
    host        TEXT        NOT NULL,
    pattern     TEXT        NOT NULL,
    statut      TEXT        DEFAULT 'a_voir',   -- ∈ config.STATUTS_LEAD
    note        TEXT,
    updated_at  TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (host, pattern)
);
