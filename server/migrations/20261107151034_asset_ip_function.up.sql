-- The address of an ip_address asset as inet, for the ip filter of the search box
-- (docs/architecture/query-language.md, "Short form"). The asset name of an
-- ip_address asset is its address; anything that is not one bare address (a range,
-- a name, a zone id) gives NULL. IMMUTABLE so an index can be built on it: the
-- result depends on the text alone.
--
-- Live impact: creates a function only; no table is read or locked.
CREATE OR REPLACE FUNCTION parse_asset_ip(name text) RETURNS inet
    LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE
    SET search_path = pg_catalog
AS $$
BEGIN
    -- Only characters an address can hold: no exception (and no subtransaction)
    -- for names that are clearly not addresses.
    IF name !~ '^\[?[0-9A-Fa-f:.]{2,45}\]?$' THEN
        RETURN NULL;
    END IF;
    RETURN host(btrim(name, '[]')::inet)::inet;
EXCEPTION WHEN invalid_text_representation THEN
    RETURN NULL;
END;
$$;

COMMENT ON FUNCTION parse_asset_ip(text) IS
    'The asset name as a single inet address (full mask), or NULL when it is not one bare address. Used by the ip filter and its index idx_assets_ip_addr.';
