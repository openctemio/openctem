-- Nothing to undo: a validated constraint is dropped by the down of the
-- migration that added it (000820, 000823).
SELECT 1;
