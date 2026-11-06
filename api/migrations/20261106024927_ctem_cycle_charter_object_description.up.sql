-- A cycle's charter is always a JSON object, and a cycle keeps its
-- description (research 458 B2, B7).
--
-- Charters saved as JSON null (a create without a charter) made the scope
-- refinement notes fail ("cannot set path in scalar"). They become {}; the
-- handler now always writes an object and the notes write normalises any
-- other value. A NOT NULL / object CHECK is left to a later contract step:
-- during a rolling deploy the previous release still writes JSON null on a
-- create without a charter. Cheap on live: a handful of cycle rows.

UPDATE ctem_cycles
   SET charter = '{}'::jsonb
 WHERE charter IS NULL OR jsonb_typeof(charter) <> 'object';

ALTER TABLE ctem_cycles DROP CONSTRAINT IF EXISTS ctem_cycles_description_length;
ALTER TABLE ctem_cycles
    ALTER COLUMN charter SET DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS description text NOT NULL DEFAULT '',
    ADD CONSTRAINT ctem_cycles_description_length CHECK (char_length(description) <= 2000);
