-- Reverse 000215: reactivate the policies module row.
UPDATE modules
SET is_active = TRUE,
    release_status = 'released'
WHERE id = 'policies';
