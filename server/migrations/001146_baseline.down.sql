-- The baseline is not reverted: there is no older schema in this tree to go
-- back to, and reverting it would drop every table. Restore a backup instead.
DO $$
BEGIN
    RAISE EXCEPTION 'migration baseline 001146 cannot be reverted; restore a database backup instead';
END
$$;
