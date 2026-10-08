-- The up migration only corrects ecosystem labels ('other' to the ecosystem
-- the package URL names); which rows were 'other' before is not recorded,
-- and putting the wrong label back would serve no one. Nothing to undo.
SELECT 1;
