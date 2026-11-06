ALTER TABLE web_endpoints DROP CONSTRAINT IF EXISTS chk_web_endpoints_resp_hash;
ALTER TABLE web_endpoints DROP CONSTRAINT IF EXISTS chk_web_endpoints_resp_size;
ALTER TABLE web_endpoints
    DROP COLUMN IF EXISTS resp_hash,
    DROP COLUMN IF EXISTS resp_size;
