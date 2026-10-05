-- "OIDC required for CI" (docs/rfcs/RFC-051-ci-runner-identity-and-gate.md):
-- when set, a CI (one-shot, runner) sensor's key is refused and a CI job must
-- prove its identity with its provider's OIDC token.
--
-- Existing organizations keep today's behaviour (false) and opt in; every
-- organization created after this migration starts with it on (the column
-- default becomes true once the existing rows have their value).
-- Live impact: a column with a constant default (no table rewrite) and a
-- default change (metadata only).

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS ci_require_oidc BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE tenants ALTER COLUMN ci_require_oidc SET DEFAULT TRUE;

COMMENT ON COLUMN tenants.ci_require_oidc IS
    'Refuse CI results sent with a CI sensor key; CI jobs must use OIDC (RFC-051). New tenants: true.';
