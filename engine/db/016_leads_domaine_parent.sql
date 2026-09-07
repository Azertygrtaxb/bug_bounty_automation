-- Domaine parent (registered-domain) porté sur `leads` : permet au dashboard de REGROUPER
-- les leads d'une même entité (tous les sous-domaines de oneytrust.com ensemble) via un
-- GROUP BY, sans recalculer côté board ni détruire le host exact (cible pour recon/hunt).
-- Rempli par engine/leads.py (scope.registered_domain(host)). Idempotent.
ALTER TABLE leads ADD COLUMN IF NOT EXISTS domaine_parent TEXT;
CREATE INDEX IF NOT EXISTS idx_leads_domaine_parent ON leads (domaine_parent);
