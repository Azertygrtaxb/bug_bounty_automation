-- Couche sémantique : verdict du juge LLM AVEUGLE par endpoint, persisté sur `targets`.
-- Le juge lit body_text DÉJÀ stocké (aucun re-fetch réseau). Un endpoint jugé
-- (semantique_juge_le NON NULL) n'est jamais re-jugé. La clé API n'apparaît nulle part ici.
ALTER TABLE targets ADD COLUMN IF NOT EXISTS semantique_faits    JSONB;       -- les 8 faits (valeurs fermées)
ALTER TABLE targets ADD COLUMN IF NOT EXISTS semantique_verdict  TEXT;        -- applicatif|surface_auth|institutionnel|incertain|EXCLU_auth_wall
ALTER TABLE targets ADD COLUMN IF NOT EXISTS semantique_juge_le  TIMESTAMPTZ; -- date de jugement (NULL = pas encore jugé)
ALTER TABLE targets ADD COLUMN IF NOT EXISTS semantique_modele   TEXT;        -- modèle utilisé (traçabilité)
ALTER TABLE targets ADD COLUMN IF NOT EXISTS semantique_tokens   JSONB;       -- {input, output, cache_read}
