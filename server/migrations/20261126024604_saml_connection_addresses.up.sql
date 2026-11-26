-- SAML addresses keyed by connection id (research 516).
--
-- The public SAML addresses (/api/v1/auth/saml/<key>/{metadata,login,acs})
-- and the SP entity ID were keyed by the organization's current slug, so a
-- renamed slug could be registered by another organization and receive the
-- first one's sign-in posts. They are now keyed by the configuration's random
-- id.
--
-- legacy_path_key: every configuration that exists now keeps its current
-- address, frozen: the identity provider already holds it. The key is copied
-- once from the slug and never follows a later rename; lookups by it never
-- read tenants.slug. Configurations created from now on never get one.
--
-- saml_connection_ids: the id a tenant's next configuration takes, reserved
-- when the administrator first reads the SP metadata, so its addresses can be
-- registered at the identity provider before the configuration is saved.
-- Deleting the configuration deletes the reservation (the address retires).

ALTER TABLE saml_providers ADD COLUMN IF NOT EXISTS legacy_path_key text;

UPDATE saml_providers s
   SET legacy_path_key = t.slug
  FROM tenants t
 WHERE t.id = s.tenant_id
   AND s.legacy_path_key IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_saml_providers_legacy_path_key
    ON saml_providers (legacy_path_key) WHERE legacy_path_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS saml_connection_ids (
    tenant_id     uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    connection_id uuid NOT NULL UNIQUE,
    created_at    timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN saml_providers.legacy_path_key IS
    'Frozen pre-connection-id address key (the slug when the configuration was migrated); NULL for newer configurations';
COMMENT ON TABLE saml_connection_ids IS
    'Connection id reserved for a tenant''s next SAML configuration (its public addresses), removed with the configuration';
