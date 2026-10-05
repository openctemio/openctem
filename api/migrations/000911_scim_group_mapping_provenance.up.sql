-- Who configured each SCIM group -> role mapping (23b S-H1).
--
-- Granting or removing the admin role through SCIM is allowed only by a
-- mapping the organization's owner configured. Existing rows predate this, so
-- configured_by_owner starts FALSE: an existing admin mapping stops granting
-- (or removing) admin until an owner saves it again. Nobody is demoted by
-- this migration; member/viewer mappings are unaffected.
--
-- Metadata-only ALTERs on a small table (constant defaults, nullable FK).
ALTER TABLE scim_group_role_mappings
    ADD COLUMN IF NOT EXISTS configured_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS configured_by_owner BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

COMMENT ON COLUMN scim_group_role_mappings.configured_by IS
    'User who last set this mapping (NULL: predates provenance, or the user was deleted).';
COMMENT ON COLUMN scim_group_role_mappings.configured_by_owner IS
    'TRUE when configured_by was the organization owner at the time; only such an admin mapping may grant or remove admin via SCIM.';
