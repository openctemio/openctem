ALTER TABLE ci_oidc_replay
    DROP COLUMN IF EXISTS first_at,
    DROP COLUMN IF EXISTS exchanges,
    DROP COLUMN IF EXISTS run_id,
    DROP COLUMN IF EXISTS token_sha256,
    DROP COLUMN IF EXISTS tenant_id;

COMMENT ON TABLE ci_oidc_replay IS 'OIDC token ids already exchanged for a CI upload token (RFC-051). Global by design: a token is good for one exchange.';

COMMENT ON TABLE ci_run_tokens IS 'Upload token hashes (SHA-256) of the jobs of an aggregate CI run, one per job exchange. The token itself is never stored. Deleted with the run, and by the CI retention job once expired.';
