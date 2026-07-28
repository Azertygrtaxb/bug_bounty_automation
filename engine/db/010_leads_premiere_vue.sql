-- « NOUVEAU DEPUIS » (retex reNgine) : première-vue d'un lead = MIN(targets.cree_le)
-- sur les membres du groupe. hash_dedup est UNIQUE (pas de ré-insert), donc cree_le est
-- une vraie première-vue. Recalculée à chaque rebuild depuis `targets` : rien à préserver.
ALTER TABLE leads ADD COLUMN IF NOT EXISTS premiere_vue TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_leads_premiere_vue ON leads (premiere_vue DESC);
