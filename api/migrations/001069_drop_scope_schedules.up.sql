-- expand-contract-ok: contract step; the previous release only touches scan_schedules from the /api/v1/scope/schedules routes, which nothing calls (the web removed the Scope Schedules tab) and which this change removes; the table is empty.
-- Drop scan_schedules, the storage of the inert scope schedules
-- (legacy cleanup, wave 4).
--
-- Scope schedules never ran a scan: nothing called ListDueSchedules and
-- "run now" only recorded a status. The Scope Config Schedules tab was
-- removed from the web (Scoping IA decision D10); scans are scheduled by the
-- Scans scheduler. 0 rows on a production restore. The routes, handler,
-- service, domain types and repository are removed in the same change.
--
-- Tenant isolation: unchanged; the table takes its own shadow RLS policy.

DROP TABLE IF EXISTS public.scan_schedules;
