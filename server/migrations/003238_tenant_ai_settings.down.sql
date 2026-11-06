-- Put the organization AI settings back into tenants.settings.ai. The
-- ciphertext keeps the "enc:v1:" prefix the JSON form used.
UPDATE tenants t
   SET settings = jsonb_set(COALESCE(t.settings, '{}'::jsonb), '{ai}',
       jsonb_strip_nulls(jsonb_build_object(
           'mode', CASE s.source WHEN 'own' THEN 'byok' WHEN 'off' THEN 'disabled' ELSE 'platform' END,
           'provider', NULLIF(s.provider, ''),
           'model_override', NULLIF(s.model, ''),
           'api_key', CASE WHEN s.key_enc IS NOT NULL THEN 'enc:v1:' || s.key_enc END,
           'enabled_at', CASE WHEN s.enabled_at IS NOT NULL THEN to_char(s.enabled_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') END,
           'enabled_by', NULLIF(s.enabled_by, '')) || s.policy), true)
  FROM tenant_ai_settings s
 WHERE s.tenant_id = t.id;

DROP TABLE tenant_ai_settings;
