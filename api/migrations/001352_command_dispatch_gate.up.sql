-- The dispatch-gate inputs a command's targets passed when it was created
-- (probe tier, passive stage, act scope and the actor it acts for), so the
-- claim re-applies the same gate before a sensor gets the job: scope can
-- change while the job waits in the queue. Written by the platform only,
-- never sent to a sensor. Nullable, no backfill: a scan command without it
-- is re-checked with the baseline gate (exclusions, rejected names, zones).
-- Architecture: docs/architecture/active-probe-gate.md.
ALTER TABLE commands
    ADD COLUMN IF NOT EXISTS dispatch_gate jsonb;
