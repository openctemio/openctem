UPDATE tools SET output_types = ARRAY['service/discovered_url']
 WHERE tenant_id IS NULL AND name = 'katana' AND output_types = ARRAY['service/http'];

DROP TABLE IF EXISTS web_endpoint_params;
DROP TABLE IF EXISTS web_endpoints;
