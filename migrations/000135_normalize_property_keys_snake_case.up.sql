-- Migration: Normalize camelCase JSONB property keys to snake_case
-- This ensures consistency: collectors send snake_case, UI reads snake_case.
-- The backend PromoteKnownProperties now auto-converts camelCase on ingest,
-- but existing data needs a one-time cleanup.

-- Helper function: convert a single camelCase string to snake_case
CREATE OR REPLACE FUNCTION pg_temp.camel_to_snake(s TEXT) RETURNS TEXT AS $$
DECLARE
    result TEXT := '';
    ch CHAR;
    prev_ch CHAR := '';
    i INT;
BEGIN
    FOR i IN 1..length(s) LOOP
        ch := substr(s, i, 1);
        IF ch >= 'A' AND ch <= 'Z' THEN
            -- Insert underscore before uppercase if preceded by lowercase
            IF prev_ch >= 'a' AND prev_ch <= 'z' THEN
                result := result || '_';
            -- Or if preceded by uppercase and followed by lowercase (e.g., "memoryGB" → "memory_gb")
            ELSIF prev_ch >= 'A' AND prev_ch <= 'Z' AND i < length(s) AND substr(s, i+1, 1) >= 'a' AND substr(s, i+1, 1) <= 'z' THEN
                result := result || '_';
            END IF;
            result := result || lower(ch);
        ELSE
            result := result || ch;
        END IF;
        prev_ch := ch;
    END LOOP;
    RETURN result;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Helper function: recursively normalize all keys in a JSONB object
CREATE OR REPLACE FUNCTION pg_temp.normalize_jsonb_keys(obj JSONB) RETURNS JSONB AS $$
DECLARE
    result JSONB := '{}';
    kv RECORD;
    new_key TEXT;
BEGIN
    IF obj IS NULL OR jsonb_typeof(obj) != 'object' THEN
        RETURN obj;
    END IF;
    FOR kv IN SELECT * FROM jsonb_each(obj) LOOP
        new_key := pg_temp.camel_to_snake(kv.key);
        -- If snake_case key already exists, don't overwrite it
        IF result ? new_key AND new_key != kv.key THEN
            CONTINUE;
        END IF;
        -- Recursively normalize nested objects (but not arrays)
        IF jsonb_typeof(kv.value) = 'object' THEN
            result := result || jsonb_build_object(new_key, pg_temp.normalize_jsonb_keys(kv.value));
        ELSE
            result := result || jsonb_build_object(new_key, kv.value);
        END IF;
    END LOOP;
    RETURN result;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Apply normalization to all assets with properties containing camelCase keys
-- Only update rows where at least one key changes (avoid unnecessary writes)
UPDATE assets
SET properties = pg_temp.normalize_jsonb_keys(properties),
    updated_at = NOW()
WHERE properties IS NOT NULL
  AND properties != '{}'::jsonb
  AND properties::text ~ '[a-z][A-Z]';  -- Quick regex check: has camelCase pattern
