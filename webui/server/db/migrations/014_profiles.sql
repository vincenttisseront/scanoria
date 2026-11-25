-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Copyright (C) 2026 Vincent Tisseront
--
-- 0.7, chantier C (G8) : profils archivables et hiérarchie sans cycle. Un
-- parent a toujours un niveau strictement supérieur (team → enterprise ;
-- project → enterprise ou team) : aucun cycle n'est possible et la
-- profondeur est au plus 3.

ALTER TABLE profiles
    ADD COLUMN archived_at timestamptz,
    ADD COLUMN updated_by bigint REFERENCES users (id) ON DELETE SET NULL;

CREATE FUNCTION profiles_check_hierarchy() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE plevel text;
BEGIN
    -- Un profil d'entreprise avec parent est refusé par profiles_level_parent (013).
    IF NEW.parent_id IS NOT NULL AND NEW.level <> 'enterprise' THEN
        SELECT level INTO plevel FROM profiles WHERE id = NEW.parent_id FOR SHARE;
        IF NOT ((NEW.level = 'team' AND plevel = 'enterprise')
                OR (NEW.level = 'project' AND plevel IN ('enterprise', 'team'))) THEN
            RAISE EXCEPTION 'profile parent must have a higher level'
                USING ERRCODE = 'check_violation', CONSTRAINT = 'profiles_parent_level';
        END IF;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.level IS DISTINCT FROM OLD.level AND EXISTS (
        SELECT 1 FROM profiles c
         WHERE c.parent_id = NEW.id
           AND NOT ((c.level = 'team' AND NEW.level = 'enterprise')
                    OR (c.level = 'project' AND NEW.level IN ('enterprise', 'team')))) THEN
        RAISE EXCEPTION 'profile children must have a lower level'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'profiles_parent_level';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER profiles_hierarchy BEFORE INSERT OR UPDATE OF parent_id, level ON profiles
    FOR EACH ROW EXECUTE FUNCTION profiles_check_hierarchy();
<<<<<<< HEAD
=======

-- G9 : profil par déclencheur, avec les défauts de l'entreprise (principe 8) :
-- PR → rapide, nuit → complet, release → release (tous les modules). Un champ
-- vide renvoie toujours à profile_id (contrat 29).
UPDATE projects p
   SET profile_pr_id = COALESCE(p.profile_pr_id, (SELECT id FROM profiles WHERE slug = 'rapide' AND builtin)),
       profile_nightly_id = COALESCE(p.profile_nightly_id, (SELECT id FROM profiles WHERE slug = 'complet' AND builtin)),
       profile_release_id = COALESCE(p.profile_release_id, (SELECT id FROM profiles WHERE slug = 'release' AND builtin))
 WHERE p.profile_pr_id IS NULL OR p.profile_nightly_id IS NULL OR p.profile_release_id IS NULL;
>>>>>>> origin/main
