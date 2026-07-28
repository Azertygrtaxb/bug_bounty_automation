-- Un statut dont la clé (host, pattern) n'existe plus dans `leads` après un rebuild
-- (pattern replié différemment, endpoint disparu) est un ORPHELIN. On NE le supprime
-- JAMAIS (c'est du travail humain) : on le marque, et `leads.py --orphelins` les liste.
ALTER TABLE leads_statut ADD COLUMN IF NOT EXISTS orphelin BOOLEAN DEFAULT false;
