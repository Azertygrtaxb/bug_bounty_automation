-- OPS (Tier 5) — FILE DE TRAVAUX : le board DEMANDE, un runner sur chaque VPS EXÉCUTE.
--
-- POURQUOI UNE FILE EN BASE plutôt qu'un appel direct depuis le board :
-- le board tourne dans un conteneur, sans docker.sock ni clé SSH, et les scripts qu'il
-- s'agit de lancer (recon.sh, hunt.sh) vivent sur l'HÔTE — et pas sur la même machine :
-- la recon est sur le VPS de reconnaissance, la chasse sur le VPS de chasse. Donner au
-- board de quoi exécuter du code hôte reviendrait à transformer une page web en
-- exécution de commandes distante ; il suffirait d'un mot de passe fuité. Il écrit donc
-- une LIGNE, et le runner de la machine concernée vient la prendre. La surface d'attaque
-- se réduit à ce que le runner accepte de lire (host + options en liste blanche).
--
-- SÉPARATION AVEC bb_pipeline_runs, qui existe déjà :
--   bb_jobs           = l'EXÉCUTION   (qui a cliqué, quel PID, coupé ou non, rc)
--   bb_pipeline_runs  = le RÉSULTAT   (urls trouvées, couverture nuclei, findings)
-- Un job annulé au bout de trois minutes a sa ligne ici et n'a rien à dire là-bas.
-- Les deux tables ne se remplacent pas : sans bb_jobs on ne saurait jamais qu'une
-- chasse a été coupée à la main plutôt que terminée.

CREATE TABLE IF NOT EXISTS bb_jobs (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host         TEXT NOT NULL,
    phase        TEXT NOT NULL CHECK (phase IN ('recon', 'hunt')),
    etat         TEXT NOT NULL DEFAULT 'en_attente'
                 CHECK (etat IN ('en_attente', 'en_cours', 'termine', 'echec', 'annule')),
    -- Options validées en LISTE BLANCHE côté board (engine/ops.py) puis RE-validées par
    -- le runner avant de construire l'argv. Elles finissent en arguments de shell : une
    -- valeur libre ici serait une injection de commande sur l'hôte.
    options      JSONB NOT NULL DEFAULT '{}'::jsonb,
    demande_par  TEXT,
    demande_le   TIMESTAMPTZ NOT NULL DEFAULT now(),
    debut_le     TIMESTAMPTZ,
    fin_le       TIMESTAMPTZ,
    runner       TEXT,
    pgid         INTEGER,          -- groupe de processus : permet de tuer TOUT l'arbre
    rc           INTEGER,
    message      TEXT,
    stop_demande BOOLEAN NOT NULL DEFAULT false
);

-- Un seul job VIVANT par (host, phase). Deux recons simultanées sur la même cible
-- écriraient dans le même out/<host>/ et se corrompraient mutuellement ; deux chasses
-- se marcheraient sur le journal.
CREATE UNIQUE INDEX IF NOT EXISTS bb_jobs_actif_idx
    ON bb_jobs (host, phase) WHERE etat IN ('en_attente', 'en_cours');
CREATE INDEX IF NOT EXISTS bb_jobs_file_idx ON bb_jobs (phase, etat, id);
CREATE INDEX IF NOT EXISTS bb_jobs_recent_idx ON bb_jobs (demande_le DESC);

-- ─────────────────────────────────────────────────────── interrupteur global ──
-- Le bouton on/off. `actif=false` : les runners cessent de PRENDRE de nouveaux jobs ;
-- ce qui tourne continue. Couper une chasse en cours est une action distincte et
-- explicite (stop_demande sur le job, ou « tout couper ») — sans quoi un clic
-- malheureux tuerait une session Claude à 3 h 50 sur un plafond de 4 h.
CREATE TABLE IF NOT EXISTS bb_controle (
    cle     TEXT PRIMARY KEY,      -- 'recon' | 'hunt'
    actif   BOOLEAN NOT NULL DEFAULT true,
    maj_le  TIMESTAMPTZ NOT NULL DEFAULT now(),
    maj_par TEXT
);
INSERT INTO bb_controle (cle, actif) VALUES ('recon', true), ('hunt', true)
    ON CONFLICT (cle) DO NOTHING;

-- ──────────────────────────────────────────────────────── présence des runners ──
-- Sans ce battement de cœur, un clic sur « lancer » resterait en_attente pour
-- toujours si le runner de la machine est mort, et la page afficherait « en attente »
-- avec l'air de fonctionner. On affiche donc l'âge du dernier signe de vie.
-- `hotes_prets` = les cibles dont la recon est complète SUR CETTE MACHINE : c'est ce
-- qui permet au board de savoir si une chasse est lançable avant de la proposer.
CREATE TABLE IF NOT EXISTS bb_runners (
    nom         TEXT PRIMARY KEY,
    phase       TEXT NOT NULL,
    vu_le       TIMESTAMPTZ NOT NULL DEFAULT now(),
    jobs_max    INTEGER,
    jobs_actifs INTEGER,
    ip_sortie   TEXT,
    version     TEXT,
    hotes_prets TEXT[]
);

-- ────────────────────────────────────────────────────────────────── droits ──
-- Le board tourne avec board_ro (SELECT sur leads/targets, écriture sur leads_statut).
-- Il lui faut ici : insérer un job, demander un arrêt, basculer l'interrupteur, lire
-- l'état. Il n'a JAMAIS besoin de DELETE — l'historique des lancements reste entier.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'board_ro') THEN
        GRANT SELECT, INSERT, UPDATE ON bb_jobs      TO board_ro;
        GRANT SELECT, UPDATE          ON bb_controle TO board_ro;
        GRANT SELECT                  ON bb_runners  TO board_ro;
        -- Lecture seule des résultats, pour afficher l'état par host à côté du bouton.
        IF to_regclass('public.bb_pipeline_runs') IS NOT NULL THEN
            GRANT SELECT ON bb_pipeline_runs TO board_ro;
        END IF;
        IF to_regclass('public.bb_pipeline_status') IS NOT NULL THEN
            GRANT SELECT ON bb_pipeline_status TO board_ro;
        END IF;
    END IF;
END $$;
