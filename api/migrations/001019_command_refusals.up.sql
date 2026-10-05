-- Sensor refusals of a command (research/25 §3.6, owner decision D8).
--
-- A sensor that refuses a job under its policy (local policy, managed
-- layer, built-in deny list) reports the refusal; the platform re-queues
-- routed scan work to another eligible sensor and excludes the refuser at
-- claim. It fails the command once no other eligible sensor accepts it or
-- after 3 refusals, with the aggregated reasons.
--
-- refused_by: the sensors that refused it (the claim predicate excludes them).
-- refusals:   bounded list of {sensor_id, layer, rule, detail, at}, for the
--             final failure message and the UI.
--
-- Additive with constant defaults: no table rewrite on a populated table
-- (PostgreSQL 11+ keeps the default in the catalog).

ALTER TABLE commands
    ADD COLUMN IF NOT EXISTS refused_by uuid[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS refusals jsonb NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE commands
    DROP CONSTRAINT IF EXISTS chk_commands_refusals_shape,
    ADD CONSTRAINT chk_commands_refusals_shape
        CHECK (jsonb_typeof(refusals) = 'array' AND cardinality(refused_by) <= 16);

COMMENT ON COLUMN commands.refused_by IS 'Sensors that refused this command under their policy (research/25 D8); they cannot claim it again.';
COMMENT ON COLUMN commands.refusals IS 'The refusals of this command: [{sensor_id, layer, rule, detail, at}] (research/25 D8).';
