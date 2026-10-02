-- Reverse 000187: reactivate the legacy duplicate module rows.
UPDATE modules
SET is_active = TRUE,
    release_status = 'released'
WHERE id IN ('scope', 'secrets', 'sources', 'webhooks', 'pipelines');
