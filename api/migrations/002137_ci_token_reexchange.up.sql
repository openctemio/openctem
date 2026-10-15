-- Idempotent CI token re-exchange (RFC-051).
--
-- A CI job's OIDC token used to be good for exactly one exchange. A job that
-- lost the answer to its exchange (a timeout, a 5xx, a second openctem-ci
-- step in the same job) could not report at all. The replay record now keeps
-- what the first exchange produced, so the same token presented again, while
-- it is still valid, gets a fresh upload token for the SAME run and nothing
-- else:
--
--   tenant_id     the organization the token was admitted into; a
--                 re-exchange into another organization is refused. Set to
--                 NULL when the organization is deleted: the token id stays
--                 claimed (refused), and no row names the deleted tenant;
--   token_sha256  SHA-256 of the exact token: same issuer and jti with other
--                 bytes is refused as a replay;
--   run_id        the run the token opened or joined (NULL until known);
--   exchanges     how many times the token was exchanged (bounded by the
--                 service);
--   first_at      when it was first exchanged (shown in refusals).
--
-- Rows written before this migration have no tenant or digest: such a token
-- is refused on a second exchange, as before. Rows live as long as the token
-- (expires_at) and are purged as before.
--
-- Nullable columns and non-volatile defaults: no table rewrite, no backfill.

ALTER TABLE ci_oidc_replay
    ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES tenants (id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS token_sha256 bytea,
    ADD COLUMN IF NOT EXISTS run_id uuid,
    ADD COLUMN IF NOT EXISTS exchanges integer DEFAULT 1 NOT NULL,
    ADD COLUMN IF NOT EXISTS first_at timestamp with time zone DEFAULT now() NOT NULL;

COMMENT ON TABLE ci_oidc_replay IS 'OIDC token ids already exchanged for a CI upload token (RFC-051). Global by design. The same token (same digest, same organization) may be exchanged again, a bounded number of times, and gets a token for the same run only.';

COMMENT ON TABLE ci_run_tokens IS 'Upload token hashes (SHA-256) of a CI run beyond ci_runs.token_hash: one per job of an aggregate run, and one per re-exchange of the token that opened a run. The token itself is never stored. Deleted with the run, and by the CI retention job once expired.';
