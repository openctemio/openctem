-- =============================================================================
-- Migration 046: JSONB Deep Merge Functions
-- =============================================================================
-- Provides intelligent JSONB merging for asset property upserts.
-- merge_jsonb_deep() is used by asset bulk upsert (ON CONFLICT) to merge
-- properties without losing nested keys.

-- -----------------------------------------------------------------------------
-- 1. merge_jsonb_arrays_by_key: Merge JSONB arrays with deduplication
-- -----------------------------------------------------------------------------
-- Used for deduplicating dns_records, ports, etc. by composite unique key.

CREATE OR REPLACE FUNCTION merge_jsonb_arrays_by_key(
    base JSONB,
    new_data JSONB,
    unique_keys TEXT[]
) RETURNS JSONB AS $$
DECLARE
    result JSONB;
    elem JSONB;
    existing_keys TEXT[];
    elem_key TEXT;
    key_parts TEXT[];
BEGIN
    -- Handle nulls
    IF base IS NULL THEN RETURN new_data; END IF;
    IF new_data IS NULL THEN RETURN base; END IF;

    -- Start with base array
    result := base;
    existing_keys := ARRAY[]::TEXT[];

    -- Build list of existing unique keys from base
    FOR elem IN SELECT jsonb_array_elements(base)
    LOOP
        key_parts := ARRAY[]::TEXT[];
        FOR i IN 1..array_length(unique_keys, 1)
        LOOP
            key_parts := array_append(key_parts, COALESCE(elem->>unique_keys[i], ''));
        END LOOP;
        existing_keys := array_append(existing_keys, array_to_string(key_parts, ':'));
    END LOOP;

    -- Add non-duplicate elements from new_data
    FOR elem IN SELECT jsonb_array_elements(new_data)
    LOOP
        key_parts := ARRAY[]::TEXT[];
        FOR i IN 1..array_length(unique_keys, 1)
        LOOP
            key_parts := array_append(key_parts, COALESCE(elem->>unique_keys[i], ''));
        END LOOP;
        elem_key := array_to_string(key_parts, ':');

        IF NOT elem_key = ANY(existing_keys) THEN
            result := result || jsonb_build_array(elem);
            existing_keys := array_append(existing_keys, elem_key);
        END IF;
    END LOOP;

    RETURN result;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION merge_jsonb_arrays_by_key(JSONB, JSONB, TEXT[]) IS
    'Merges two JSONB arrays, deduplicating by composite unique key. Used for recon data merging.';

-- -----------------------------------------------------------------------------
-- 2. merge_jsonb_deep: Deep merge two JSONB objects with smart array handling
-- -----------------------------------------------------------------------------
-- Merge strategies by key name:
--   dns_records       → dedupe by (type, name, value)
--   ports             → dedupe by (port, protocol)
--   technologies, nameservers, sans → union unique strings
--   nested objects    → recursive merge
--   scalars/other     → new_data wins

CREATE OR REPLACE FUNCTION merge_jsonb_deep(base JSONB, new_data JSONB) RETURNS JSONB AS $$
DECLARE
    result JSONB;
    key TEXT;
    base_val JSONB;
    new_data_val JSONB;
BEGIN
    -- Handle nulls
    IF base IS NULL THEN RETURN new_data; END IF;
    IF new_data IS NULL THEN RETURN base; END IF;

    -- Start with base
    result := base;

    -- Iterate through new_data keys
    FOR key IN SELECT jsonb_object_keys(new_data)
    LOOP
        base_val := result->key;
        new_data_val := new_data->key;

        -- Handle different merge strategies based on key name
        IF key IN ('dns_records') THEN
            -- DNS records: dedupe by (type, name, value)
            result := jsonb_set(
                result,
                ARRAY[key],
                merge_jsonb_arrays_by_key(base_val, new_data_val, ARRAY['type', 'name', 'value'])
            );
        ELSIF key IN ('ports') THEN
            -- Ports: dedupe by (port, protocol)
            result := jsonb_set(
                result,
                ARRAY[key],
                merge_jsonb_arrays_by_key(base_val, new_data_val, ARRAY['port', 'protocol'])
            );
        ELSIF key IN ('technologies', 'nameservers', 'sans') THEN
            -- Simple string arrays: union unique
            IF jsonb_typeof(base_val) = 'array' AND jsonb_typeof(new_data_val) = 'array' THEN
                result := jsonb_set(
                    result,
                    ARRAY[key],
                    (SELECT jsonb_agg(DISTINCT value) FROM (
                        SELECT value FROM jsonb_array_elements(base_val)
                        UNION
                        SELECT value FROM jsonb_array_elements(new_data_val)
                    ) t)
                );
            ELSE
                result := jsonb_set(result, ARRAY[key], new_data_val);
            END IF;
        ELSIF jsonb_typeof(base_val) = 'object' AND jsonb_typeof(new_data_val) = 'object' THEN
            -- Nested objects: recursive merge
            result := jsonb_set(result, ARRAY[key], merge_jsonb_deep(base_val, new_data_val));
        ELSE
            -- Scalars and other: new_data wins
            result := jsonb_set(result, ARRAY[key], new_data_val);
        END IF;
    END LOOP;

    RETURN result;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

COMMENT ON FUNCTION merge_jsonb_deep(JSONB, JSONB) IS
    'Deep merges two JSONB objects with intelligent array deduplication for recon data fields.';
