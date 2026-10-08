-- No-op by design. 001334 moved the CTIS technical blocks' facts to flat
-- property keys and removed the blocks (a data fix). It is not reversible:
-- the flat keys may also have held their own values, and every write path
-- now stores flat keys. Rolling back the schema needs nothing here.
SELECT 1;
