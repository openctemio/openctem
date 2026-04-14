-- Indexes for IP-hostname correlation during asset ingestion.
-- Enables fast lookup: "find host that has this IP in properties"

-- Index on properties.ip (flat key used by host assets)
CREATE INDEX IF NOT EXISTS idx_assets_props_ip
    ON assets ((properties->>'ip'))
    WHERE properties->>'ip' IS NOT NULL;

-- Index on properties.ip_address.address (structured key used by ip_address assets)
CREATE INDEX IF NOT EXISTS idx_assets_props_ip_addr
    ON assets ((properties->'ip_address'->>'address'))
    WHERE properties->'ip_address'->>'address' IS NOT NULL;

-- GIN index on properties.ip_addresses array (host with multiple IPs)
CREATE INDEX IF NOT EXISTS idx_assets_props_ip_addresses
    ON assets USING GIN ((properties->'ip_addresses'))
    WHERE properties->'ip_addresses' IS NOT NULL;

-- Index on properties.hostname (reverse lookup: find asset by hostname)
CREATE INDEX IF NOT EXISTS idx_assets_props_hostname
    ON assets ((properties->>'hostname'))
    WHERE properties->>'hostname' IS NOT NULL;

-- Index on properties.ip_address.hostname (structured key)
CREATE INDEX IF NOT EXISTS idx_assets_props_ip_hostname
    ON assets ((properties->'ip_address'->>'hostname'))
    WHERE properties->'ip_address'->>'hostname' IS NOT NULL;
