DROP TABLE IF EXISTS proxy_endpoint_exits;
DROP TABLE IF EXISTS proxy_echo_observations;
ALTER TABLE proxy_endpoints DROP CONSTRAINT IF EXISTS uq_proxy_endpoints_tenant_pool_id;
