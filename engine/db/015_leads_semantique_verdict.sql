-- Verdict sémantique porté sur la table `leads` (colonne DÉDIÉE, en plus de sa présence
-- dans `raisons`) : le dashboard peut l'afficher comme badge / filtrer dessus sans parser
-- le texte des raisons. Rempli par engine/leads.py (verdict du représentant = endpoint au
-- score max du groupe). NULL = pas encore jugé. Idempotent.
ALTER TABLE leads ADD COLUMN IF NOT EXISTS semantique_verdict TEXT;
