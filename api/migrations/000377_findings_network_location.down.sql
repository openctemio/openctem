ALTER TABLE findings
    DROP COLUMN IF EXISTS network_service,
    DROP COLUMN IF EXISTS network_transport,
    DROP COLUMN IF EXISTS network_port;
