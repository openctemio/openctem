-- Response evidence of a web endpoint (docs/rfcs/RFC-056-web-attack-surface.md,
-- amendment 2026-11-05).
--
-- A path found by path discovery is stored only with the evidence that the
-- answer differed from the origin's not-found answer: the size of the
-- response body and the first 16 hex characters of the sha-256 of its
-- normalised form. The body itself never leaves the sensor. Both columns are
-- nullable (rows found by a crawl carry none) and are not part of
-- response_sig, so a dynamic page does not re-plan its verification on every
-- sighting.
--
-- Additive: two nullable columns with CHECKs that hold for NULL; no rewrite,
-- no backfill. The source value `guess` needs no change: web_endpoints.sources
-- has no CHECK.

ALTER TABLE web_endpoints
    ADD COLUMN IF NOT EXISTS resp_size integer,
    ADD COLUMN IF NOT EXISTS resp_hash character(16);

ALTER TABLE web_endpoints DROP CONSTRAINT IF EXISTS chk_web_endpoints_resp_size;
ALTER TABLE web_endpoints
    ADD CONSTRAINT chk_web_endpoints_resp_size CHECK (resp_size IS NULL OR resp_size >= 0);

ALTER TABLE web_endpoints DROP CONSTRAINT IF EXISTS chk_web_endpoints_resp_hash;
ALTER TABLE web_endpoints
    ADD CONSTRAINT chk_web_endpoints_resp_hash CHECK (resp_hash IS NULL OR resp_hash ~ '^[0-9a-f]{16}$');

COMMENT ON COLUMN web_endpoints.resp_size IS 'Response body size in bytes from the last confirmed path discovery hit (NULL when not found by discovery)';
COMMENT ON COLUMN web_endpoints.resp_hash IS 'First 16 hex characters of the sha-256 of the normalised response body from path discovery (never the body)';
