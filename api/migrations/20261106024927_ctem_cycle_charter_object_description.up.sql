-- A cycle's charter is always a JSON object, and a cycle keeps its
-- description (research 458 B2, B7).
--
-- Charters saved as JSON null (a create without a charter) made the scope
-- refinement notes fail ("cannot set path in scalar"). They become {} and a
-- CHECK keeps them objects. Cheap on live: a handful of cycle rows per tenant.

UPDATE ctem_cycles
   SET charter = '{}'::jsonb
 WHERE charter IS NULL OR jsonb_typeof(charter) <> 'object';

ALTER TABLE ctem_cycles
    ALTER COLUMN charter SET DEFAULT '{}'::jsonb,
    ALTER COLUMN charter SET NOT NULL,
    ADD CONSTRAINT ctem_cycles_charter_object CHECK (jsonb_typeof(charter) = 'object'),
    ADD COLUMN IF NOT EXISTS description text NOT NULL DEFAULT '',
    ADD CONSTRAINT ctem_cycles_description_length CHECK (char_length(description) <= 2000);
