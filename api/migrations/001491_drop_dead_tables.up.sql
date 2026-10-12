-- Drop four tables nothing writes:
--   tool_executions     a per-tool run history that no code path ever
--                       recorded; its only reader was the tool list
--                       include=stats, which therefore always reported zero
--                       runs (removed with this migration)
--   component_licenses  the shared component -> license junction; licenses are
--                       the tenant's own observation (asset_components.license)
--                       plus the license dictionary (licenses)
--   attack_paths,       persisted attack paths; paths and exposure chains are
--   attack_path_nodes   computed on demand from the asset graph, and only the
--                       demo seed ever wrote these (3 demo rows each on live)
--
-- expand-contract-ok: contract step; nothing reads these tables after this change
DROP TABLE IF EXISTS tool_executions;
DROP TABLE IF EXISTS component_licenses;
DROP TABLE IF EXISTS attack_path_nodes;
DROP TABLE IF EXISTS attack_paths;
