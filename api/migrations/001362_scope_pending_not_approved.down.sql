-- The up migration clears an approval time that never was one (pending or
-- rejected entries). Putting a false approval time back would serve no
-- one, and the old values are not recorded. Nothing to undo.
SELECT 1;
