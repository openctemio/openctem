-- Deterministic keys for the vulnerability catalog (docs/rfcs/RFC-143-vulnerability-catalog.md §6):
-- a global product's id is uuidv5 over its canonical product key, and a global version's id is
-- uuidv5 over its identity (the columns of ux_software_versions_identity). A catalog rebuilt
-- anywhere gives the same ids, so tenant rows never need remapping.
--
-- This migration only adds the functions; new global rows use them. It changes no existing row:
-- rekeying the rows written before it is a separate, rehearsed migration.
--
-- The namespace UUIDs never change (changing one changes every id). pkg/domain/vulncatalog/keys.go
-- computes the same values in Go, and a test compares both.

-- Escapes the separators of a key part (backslash, colon, slash), so joined keys stay distinct.
CREATE OR REPLACE FUNCTION vuln_catalog_key_escape(v text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$ SELECT replace(replace(replace(v, E'\\', E'\\\\'), ':', E'\\:'), '/', E'\\/') $$;

-- The canonical key of a global product: its CPE (part, vendor, product) when it has one,
-- else its package URL (type, namespace, name); NULL when it has neither.
CREATE OR REPLACE FUNCTION vuln_catalog_product_key(
    part text, cpe_vendor text, cpe_product text, purl_type text, purl_namespace text, purl_name text
) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT CASE
        WHEN cpe_vendor IS NOT NULL AND cpe_product IS NOT NULL THEN
            'cpe:' || vuln_catalog_key_escape(part) || ':' || vuln_catalog_key_escape(cpe_vendor)
                || ':' || vuln_catalog_key_escape(cpe_product)
        WHEN purl_type IS NOT NULL AND purl_name IS NOT NULL THEN
            'purl:' || vuln_catalog_key_escape(purl_type) || '/' || vuln_catalog_key_escape(coalesce(purl_namespace, ''))
                || '/' || vuln_catalog_key_escape(purl_name)
    END
$$;

CREATE OR REPLACE FUNCTION vuln_catalog_product_id(
    part text, cpe_vendor text, cpe_product text, purl_type text, purl_namespace text, purl_name text
) RETURNS uuid
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT public.uuid_generate_v5('d0cdc07f-60f4-4ede-bd53-0791837a5d49'::uuid,
        vuln_catalog_product_key(part, cpe_vendor, cpe_product, purl_type, purl_namespace, purl_name))
$$;

-- The id of a global version: product id, scheme, the normalised version (or 'raw:' and the raw
-- string when it does not normalise), qualifier and edition.
CREATE OR REPLACE FUNCTION vuln_catalog_version_id(
    product_id uuid, scheme text, normalized text, raw text, qualifier text, edition text
) RETURNS uuid
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT public.uuid_generate_v5('4217cc2b-7a83-41b5-9bce-0806b01c2b2e'::uuid,
        product_id::text || ':' || vuln_catalog_key_escape(scheme)
            || ':' || vuln_catalog_key_escape(coalesce(normalized, 'raw:' || raw))
            || ':' || vuln_catalog_key_escape(qualifier) || ':' || vuln_catalog_key_escape(edition))
$$;

COMMENT ON FUNCTION vuln_catalog_key_escape(text) IS
    $$Escapes backslash, colon and slash in one part of a vulnerability catalog key.$$;
COMMENT ON FUNCTION vuln_catalog_product_key(text, text, text, text, text, text) IS
    $$Canonical key of a global product: cpe:<part>:<vendor>:<product>, else purl:<type>/<namespace>/<name>, else NULL.$$;
COMMENT ON FUNCTION vuln_catalog_product_id(text, text, text, text, text, text) IS
    $$Deterministic id of a global product (uuidv5 of its canonical key); vulncatalog.ProductID in Go.$$;
COMMENT ON FUNCTION vuln_catalog_version_id(uuid, text, text, text, text, text) IS
    $$Deterministic id of a version of a global product (uuidv5 of its identity); vulncatalog.VersionID in Go.$$;
