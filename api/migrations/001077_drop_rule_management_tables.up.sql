-- expand-contract-ok: contract step; no released code reads these tables. One exception: the previous release's asset merge also rewrites finding_data_sources (always empty), so an asset merge run by an old pod during the rollout window fails and can be retried.
-- Drop the custom scanner-rule management tables and finding_data_sources
-- (legacy cleanup, wave 3).
--
--   * rules, rule_sources, rule_bundles, rule_overrides, rule_sync_history
--     (000026): a rule-sync subsystem that was never wired. Its repositories
--     had no caller, its service was constructed nowhere, no route or
--     permission exposed it. Custom scanner content is handled by template
--     sources and scanner templates. 0 rows on a production restore.
--   * finding_data_sources (000014): per-finding source tracking whose
--     repository had no caller. Finding provenance lives on the finding
--     (source, ingest_channel) and in finding_sources. 0 rows.
--
-- The Go repositories, domain package and service are removed in the same
-- change. Tenant isolation: unchanged; the tables take their own shadow RLS
-- policies with them.

DROP TABLE IF EXISTS public.rule_sync_history;
DROP TABLE IF EXISTS public.rules;
DROP TABLE IF EXISTS public.rule_bundles;
DROP TABLE IF EXISTS public.rule_overrides;
DROP TABLE IF EXISTS public.rule_sources;
DROP TABLE IF EXISTS public.finding_data_sources;
