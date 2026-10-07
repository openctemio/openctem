-- Path- and method-aware scope exclusions (docs/rfcs/RFC-056-web-attack-surface.md §5).
--
-- An exclusion of type `path` becomes a web rule: a host pattern ("*",
-- "*.example.com", a host or an origin URL), a segment-aware path_prefix and
-- the HTTP methods it blocks (empty: every method). Its pattern is the host
-- pattern followed by the prefix ("*/admin/debug",
-- "https://api.example.com/admin"), so the existing one-row-per-pattern
-- uniqueness still holds. It never excludes a whole asset.
--
-- Each path exclusion has a testing mode a scope approver sets: blocked (the
-- default), read_only (GET and HEAD only) or allowed (treated as in scope),
-- with an optional testing_until after which it is blocked again.
--
-- Existing `path` rows are migrated, not deactivated: "/api/v1/*" becomes
-- host "*" + prefix "/api/v1"; "https://x.example/admin/*" becomes host
-- "https://x.example" + prefix "/admin". Over-blocking is the safe side, so a
-- pattern that does not read as a path becomes prefix "/" on its host.
--
-- web_endpoints.exclusion_id names the exclusion that holds an endpoint
-- excluded-untested (in_scope = false).
--
-- Small tables; added columns have constant defaults (no rewrite).

ALTER TABLE scope_exclusions
    ADD COLUMN IF NOT EXISTS path_prefix character varying(500),
    ADD COLUMN IF NOT EXISTS methods text[] NOT NULL DEFAULT '{}'::text[],
    ADD COLUMN IF NOT EXISTS testing character varying(10) NOT NULL DEFAULT 'blocked',
    ADD COLUMN IF NOT EXISTS testing_until timestamp with time zone,
    ADD COLUMN IF NOT EXISTS testing_changed_by character varying(200),
    ADD COLUMN IF NOT EXISTS testing_changed_at timestamp with time zone;

WITH conv AS (
    SELECT id, tenant_id, status, approved_at, created_at,
           CASE WHEN pattern ~* '^https?://[^/]+' THEN lower(substring(pattern FROM '^(https?://[^/?#]+)')) ELSE '*' END AS host,
           COALESCE(NULLIF(
               regexp_replace(regexp_replace(
                   CASE WHEN pattern ~* '^https?://[^/]+'
                        THEN COALESCE(substring(pattern FROM '^https?://[^/?#]+(/[^?#]*)'), '/')
                        ELSE regexp_replace(pattern, '^[*]+', '') END,
                   '/?[*]+$', ''), '//+', '/', 'g'),
               ''), '/') AS prefix
      FROM scope_exclusions
     WHERE exclusion_type = 'path'
), norm AS (
    SELECT id, host,
           left(CASE WHEN left(prefix, 1) = '/' THEN prefix ELSE '/' || prefix END, 500) AS prefix,
           row_number() OVER (
               PARTITION BY tenant_id, host, CASE WHEN left(prefix, 1) = '/' THEN prefix ELSE '/' || prefix END
               ORDER BY (status = 'active') DESC, (approved_at IS NOT NULL) DESC, created_at, id) AS rn
      FROM conv
), dropped AS (
    -- Two legacy patterns that read as the same rule ("/api/*" and "/api"):
    -- the same protection, one row kept (the one in effect first).
    DELETE FROM scope_exclusions s USING norm n WHERE s.id = n.id AND n.rn > 1 RETURNING s.id
)
UPDATE scope_exclusions s
   SET pattern = left(n.host || n.prefix, 500), path_prefix = n.prefix
  FROM norm n
 WHERE s.id = n.id AND n.rn = 1;

ALTER TABLE scope_exclusions
    ADD CONSTRAINT chk_scope_exclusion_testing CHECK (testing IN ('blocked', 'read_only', 'allowed')),
    ADD CONSTRAINT chk_scope_exclusion_path_rule CHECK (exclusion_type <> 'path'
        OR (path_prefix IS NOT NULL AND left(path_prefix, 1) = '/' AND right(pattern, length(path_prefix)) = path_prefix)),
    ADD CONSTRAINT chk_scope_exclusion_methods CHECK (methods <@ ARRAY['GET','HEAD','OPTIONS','POST','PUT','PATCH','DELETE']::text[]);

COMMENT ON COLUMN scope_exclusions.path_prefix IS 'path exclusions: segment-aware path prefix; the pattern is the host pattern followed by it (RFC-056).';
COMMENT ON COLUMN scope_exclusions.methods IS 'path exclusions: HTTP methods blocked; empty blocks every method.';
COMMENT ON COLUMN scope_exclusions.testing IS 'path exclusions: blocked | read_only (GET, HEAD) | allowed; set by a scope approver with step-up, audited.';
COMMENT ON COLUMN scope_exclusions.testing_until IS 'read_only or allowed ends here; blocked again after it.';

ALTER TABLE web_endpoints
    ADD COLUMN IF NOT EXISTS exclusion_id uuid REFERENCES scope_exclusions(id) ON DELETE SET NULL;

COMMENT ON COLUMN web_endpoints.exclusion_id IS 'The path exclusion that holds the endpoint excluded-untested (in_scope = false).';
