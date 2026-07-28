-- REPRISE du rush : un échec après le tier 1 (24-48 h) ne doit pas coûter tout le crawl.
-- Au fil de l'attente, rush.py marque chaque host dès que sa tâche est terminée, avec sa
-- phase. --reprendre retire ces hosts de la liste. Confiné à rush.py (les tâches worker
-- ne sont pas modifiées). PK = host : la dernière phase écrase la précédente
-- (shallow -> deep), donc phase='deep' implique shallow déjà fait.
CREATE TABLE IF NOT EXISTS rush_avancement (
    host     TEXT PRIMARY KEY,
    phase    TEXT,
    fini_le  TIMESTAMPTZ DEFAULT now()
);
