-- ANCRE du statut sur une URL RÉELLE (l'URL que l'humain regardait en jugeant).
-- v2.1 migrait le statut via `remap` (clés = patterns bruts) : ça couvre le sens
-- repli->replié, mais un statut posé sur un pattern DÉJÀ replié (/x/{*}/list/{id}) n'est
-- jamais une clé de remap -> au dé-repli il devenait orphelin. L'ancre_url permet la
-- réconciliation dans les DEUX sens (via targets.tags.lead_pattern).
ALTER TABLE leads_statut ADD COLUMN IF NOT EXISTS ancre_url TEXT;
