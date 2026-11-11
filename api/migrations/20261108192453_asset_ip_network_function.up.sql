-- The network of an ip_address asset, for the Network column, the group by
-- network and the network filter of the asset list
-- (docs/architecture/list-query-contract.md, "Asset inventory"): the /24 of
-- an IPv4 address, the /64 of an IPv6 address, NULL for a name that is not
-- one bare address (parse_asset_ip). IMMUTABLE so an index can be built on
-- it.
--
-- Measured before choosing an expression index over a stored column or a
-- side table: the assets table is a few MB on the live and production hosts
-- (about 1,300 and 3,100 rows, a few hundred addresses), and the address
-- filter already reads an expression index (idx_assets_ip_addr). An
-- expression index rewrites no row and needs no backfill.
--
-- Live impact: creates a function only; no table is read or locked.
CREATE OR REPLACE FUNCTION asset_ip_network(name text) RETURNS cidr
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    SET search_path = pg_catalog, public
AS $$
    SELECT network(set_masklen(a, CASE family(a) WHEN 4 THEN 24 ELSE 64 END))::cidr
    FROM (SELECT public.parse_asset_ip(name) AS a) x
    WHERE a IS NOT NULL
$$;

COMMENT ON FUNCTION asset_ip_network(text) IS
    'The /24 (IPv4) or /64 (IPv6) network of an address asset name, or NULL. Used by the network filter and idx_assets_ip_network.';
