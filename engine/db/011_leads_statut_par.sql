-- Le board est PARTAGÉ (deux chasseurs). On trace QUI a posé le dernier statut, pour ne
-- pas se marcher dessus (« qui est déjà sur ce lead ? »). Renseigné par le compte
-- authentifié du board ; NULL si posé hors interface (CLI).
ALTER TABLE leads_statut ADD COLUMN IF NOT EXISTS par_qui TEXT;
