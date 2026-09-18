-- Juge V2 : classification structurée de la surface du représentant d'un lead.
-- V1 est préservé dans ses colonnes semantique_* : la migration est additive et
-- permet un rollback applicatif sans perdre d'historique de décision.
ALTER TABLE targets ADD COLUMN IF NOT EXISTS juge_v2 JSONB;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS juge_v2_juge_le TIMESTAMPTZ;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS juge_v2_modele TEXT;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS juge_v2_tokens JSONB;

ALTER TABLE leads ADD COLUMN IF NOT EXISTS juge_v2 JSONB;
ALTER TABLE leads ADD COLUMN IF NOT EXISTS juge_v2_juge_le TIMESTAMPTZ;
