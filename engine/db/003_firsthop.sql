-- Capture du PREMIER-HOP de redirection, À CÔTÉ du contenu final (inchangé).
-- httpx suit toujours (contenu/hash final pour la détection catch-all) ; on
-- ajoute le statut + la destination du premier-hop pour démoter les 301
-- canoniques et flagger les open redirects — sans réseau au scoring.
ALTER TABLE targets ADD COLUMN IF NOT EXISTS first_hop_status   INT;
ALTER TABLE targets ADD COLUMN IF NOT EXISTS first_hop_location TEXT;
