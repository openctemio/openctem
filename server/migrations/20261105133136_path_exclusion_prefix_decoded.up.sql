-- Path exclusion prefixes are stored decoded (docs/rfcs/RFC-056-web-attack-surface.md §5).
--
-- The sensor compares a request's decoded path with the deny path, so a
-- prefix stored with a percent-escape ("/files/My%20Docs") never matched.
-- New prefixes are decoded on save (scope.NormalizePathPrefix). This rewrites
-- the stored ones the same way: path_prefix decoded, and pattern (host
-- pattern followed by the prefix) with it.
--
-- A row is left as stored when its prefix does not decode the way
-- NormalizePathPrefix accepts: an invalid escape or invalid UTF-8, a control
-- character, a percent sign (an escaped "%25"), a dot segment, or a "*"
-- inside a segment once decoded. Since a decoded prefix never holds a "%", a
-- row that still holds one was never rewritten: running this again (after a
-- down) changes nothing. The
-- platform still sends such a prefix as stored, so it denies at least what it
-- did. A row is also left as stored when its decoded pattern is already taken
-- by another exclusion of the tenant (the unique key), or by an earlier row of
-- this rewrite. The other exclusion denies the decoded form.
--
-- Small table (path exclusions only); one UPDATE, no lock beyond those rows.
CREATE FUNCTION pg_temp.decoded_path_prefix(p text) RETURNS text
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    bin  bytea := ''::bytea;
    m    text[];
    dec  text;
    seg  text;
    segs text[];
BEGIN
    IF p IS NULL OR position('%' IN p) = 0 OR p ~ '%(?![0-9A-Fa-f]{2})' THEN
        RETURN NULL;
    END IF;
    FOR m IN SELECT regexp_matches(p, '%([0-9A-Fa-f]{2})|([^%]+)', 'g') LOOP
        IF m[1] IS NOT NULL THEN
            bin := bin || decode(m[1], 'hex');
        ELSE
            bin := bin || convert_to(m[2], 'UTF8');
        END IF;
    END LOOP;
    IF position('\x00'::bytea IN bin) > 0 THEN
        RETURN NULL;
    END IF;
    BEGIN
        dec := convert_from(bin, 'UTF8');
    EXCEPTION WHEN OTHERS THEN
        RETURN NULL;
    END;
    IF dec ~ '[\x01-\x1f\x7f]' OR position('%' IN dec) > 0 THEN
        RETURN NULL;
    END IF;
    segs := array_remove(string_to_array(dec, '/'), '');
    FOREACH seg IN ARRAY coalesce(segs, '{}'::text[]) LOOP
        IF seg IN ('.', '..') OR (position('*' IN seg) > 0 AND seg <> '*') THEN
            RETURN NULL;
        END IF;
    END LOOP;
    WHILE cardinality(segs) > 0 AND segs[cardinality(segs)] = '*' LOOP
        segs := segs[1:cardinality(segs) - 1];
    END LOOP;
    RETURN '/' || array_to_string(segs, '/');
END $$;

WITH conv AS (
    SELECT id, tenant_id, exclusion_type, pattern, path_prefix,
           pg_temp.decoded_path_prefix(path_prefix) AS prefix
      FROM scope_exclusions
     WHERE exclusion_type = 'path'
       AND path_prefix IS NOT NULL
       AND position('%' IN path_prefix) > 0
), rewrite AS (
    SELECT id, tenant_id, exclusion_type, prefix,
           left(pattern, length(pattern) - length(path_prefix)) || prefix AS new_pattern
      FROM conv
     WHERE prefix IS NOT NULL
       AND prefix <> path_prefix
       AND right(pattern, length(path_prefix)) = path_prefix
), ranked AS (
    SELECT r.*, row_number() OVER (PARTITION BY tenant_id, exclusion_type, new_pattern ORDER BY id) AS rn
      FROM rewrite r
     WHERE length(r.new_pattern) <= 500
       AND NOT EXISTS (
           SELECT 1 FROM scope_exclusions o
            WHERE o.tenant_id = r.tenant_id AND o.exclusion_type = r.exclusion_type AND o.pattern = r.new_pattern)
)
UPDATE scope_exclusions s
   SET path_prefix = ranked.prefix,
       pattern     = ranked.new_pattern,
       updated_at  = now()
  FROM ranked
 WHERE s.id = ranked.id
   AND ranked.rn = 1;

DROP FUNCTION pg_temp.decoded_path_prefix(text);
