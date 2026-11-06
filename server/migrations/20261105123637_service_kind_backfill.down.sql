-- Removes the derived service kind keys and puts the transport of open
-- ports back where older code read it (protocol), so a rolled-back build
-- reads the same port_open dedupe key (it defaults to tcp).

UPDATE assets
SET properties = properties - 'service_kind' - 'service_category' - 'kind_source'
WHERE asset_type = 'service'
  AND jsonb_typeof(properties) = 'object'
  AND (properties ? 'service_kind' OR properties ? 'service_category' OR properties ? 'kind_source');

UPDATE assets
SET properties = properties || jsonb_build_object('protocol', properties->>'transport')
WHERE asset_type = 'service' AND sub_type = 'open_port'
  AND jsonb_typeof(properties) = 'object'
  AND NOT (properties ? 'protocol')
  AND lower(properties->>'transport') IN ('tcp', 'udp', 'sctp');
