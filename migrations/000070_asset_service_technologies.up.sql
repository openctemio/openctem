-- Add technologies array to asset_services for tracking detected tech stacks per service.
-- A single host can run multiple services with different technologies (e.g., port 443: React/Node.js,
-- port 8080: Django/Python). Storing technologies at the service level (not host level) is correct.

ALTER TABLE asset_services ADD COLUMN technologies TEXT[] DEFAULT '{}';

-- GIN index for efficient array containment queries (e.g., "find all services using React")
CREATE INDEX idx_asset_services_technologies ON asset_services USING GIN(technologies);
