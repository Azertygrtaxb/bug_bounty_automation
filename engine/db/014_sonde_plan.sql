-- Brique B : PLAN de sondes ciblées par endpoint, calculé par knowledge/routage.py à partir
-- du verdict sémantique + des score_raisons déterministes (convergence stricte). Les tâches
-- probe_* consomment ce plan APRÈS le DEEP. Recalculé à chaque score_targets (idempotent).
ALTER TABLE targets ADD COLUMN IF NOT EXISTS sonde_plan JSONB;  -- [{famille, verdict, declencheur, convergence}]
