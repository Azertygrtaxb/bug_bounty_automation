-- SCOPE dérivé de la liste lancée (registered-domains). Non effacé par les re-scores.
-- Rejoué à la création du volume ; sur base existante, engine/scope.py le crée aussi
-- (CREATE TABLE IF NOT EXISTS). La vue leads exclut les hosts hors de ces roots.
CREATE TABLE IF NOT EXISTS scope_roots (root TEXT PRIMARY KEY);
