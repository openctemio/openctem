ALTER TABLE sensor_api_keys DROP COLUMN IF EXISTS key_pepper_id;
ALTER TABLE sensors         DROP COLUMN IF EXISTS key_pepper_id;
ALTER TABLE scim_tokens     DROP COLUMN IF EXISTS key_pepper_id;
ALTER TABLE api_keys        DROP COLUMN IF EXISTS key_pepper_id;
