-- Capture de la substance de la réponse à la découverte, pour la démotion
-- consciente de la réponse au scoring (sans requête réseau).
ALTER TABLE targets ADD COLUMN IF NOT EXISTS body_hash TEXT;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS body_len  INT;
