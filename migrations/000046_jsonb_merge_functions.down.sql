-- Drop in reverse dependency order (merge_jsonb_deep depends on merge_jsonb_arrays_by_key)
DROP FUNCTION IF EXISTS merge_jsonb_deep(JSONB, JSONB);
DROP FUNCTION IF EXISTS merge_jsonb_arrays_by_key(JSONB, JSONB, TEXT[]);
