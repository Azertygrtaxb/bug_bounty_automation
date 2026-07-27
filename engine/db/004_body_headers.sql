-- Capture à la découverte du CORPS FINAL borné + des EN-TÊTES de réponse.
-- httpx télécharge déjà le corps (pour body_hash) et les en-têtes (-irr) : on les
-- stocke au lieu de les jeter. Rejoué à la création du volume ; sur une base
-- existante, appliquer ces ALTER à la main.
ALTER TABLE targets ADD COLUMN IF NOT EXISTS body_text TEXT;          -- corps FINAL borné (CORPS_MAX_STOCKE), NULL pour les assets
ALTER TABLE targets ADD COLUMN IF NOT EXISTS response_headers JSONB;  -- en-têtes de réponse (dict httpx 'header' : set_cookie, cors, server, www_authenticate...)
