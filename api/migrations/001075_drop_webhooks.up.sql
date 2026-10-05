-- expand-contract-ok: contract step; since 001032 no released code reads or writes webhooks except key rotation and the sensor-rename upgrade check, both of which stop in the same change.
-- Drop the retired outbound webhooks table (legacy cleanup).
--
-- The outbound webhooks feature never had a delivery worker; its API, routes
-- and permissions were removed by 001032 and its delivery table by 001059.
-- What was left: configuration rows (3 on the production restore, all created
-- on one day, none ever delivered) and two readers that only kept the table
-- alive: the encryption-key rotation (rewrapped the retired signing secrets)
-- and the sensor-rename upgrade check (counted agent.* event names in it).
-- Both stop reading it in the same change.
--
-- The rows are dead configuration of a removed feature and are dropped with
-- the table (owner decision). The down migration recreates the empty table.
--
-- Tenant isolation: unchanged. The table takes its own (shadow) RLS policy
-- with it; no other table is touched.

DROP TABLE IF EXISTS webhooks;
