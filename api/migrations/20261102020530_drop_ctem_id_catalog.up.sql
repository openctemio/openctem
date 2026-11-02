-- CTEM-ID codes are derived at read time from a static table in code
-- (pkg/domain/ctemid, docs/architecture/ctem-id-mapping.md); the catalog
-- copy downloaded from ctem.org is no longer kept. Global reference data:
-- no tenant data is lost.
DROP TABLE IF EXISTS public.ctem_id_catalog;
