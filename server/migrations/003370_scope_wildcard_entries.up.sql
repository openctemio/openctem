-- Scope entries that could authorize active probes of every host and
-- address. Entries of a type with no matcher (certificate, container,
-- database, mobile_app, cloud_resource, network) were compared as wildcard
-- text, so the pattern "*" covered everything; a URL or website entry could
-- carry a wildcard host and do the same. The API now refuses these patterns
-- and these types, and ignores such rows when it decides coverage. This
-- takes the existing rows out of effect and records one audit event per
-- entry, in the entry's own tenant. An active entry becomes inactive and a
-- pending one becomes rejected; the pattern and every other column stay, so
-- the owner can read what was there and add the right domain, address or
-- network instead.
--
-- Upgrade note: data change only. Probes that relied on such an entry stop
-- being authorized until a domain, address or network entry covers them.
-- expand-contract-ok: no schema change; the previous API keeps working on the changed rows

-- One statement, so the audit events and the status change commit together.
WITH hit AS (
  SELECT id, tenant_id, target_type, pattern, status AS old_status,
         CASE WHEN status = 'pending' THEN 'rejected' ELSE 'inactive' END AS new_status
    FROM scope_targets
   WHERE status IN ('active', 'pending')
     AND (
          (target_type IN ('certificate', 'container', 'database', 'mobile_app', 'cloud_resource', 'network')
           AND pattern LIKE '%*%')
       OR (target_type IN ('url', 'api', 'website')
           AND ((pattern !~* '^(https?|\*)://' AND pattern LIKE '%*%')
                OR (pattern LIKE '%://%'
                    AND (split_part(substr(pattern, strpos(pattern, '://') + 3), '/', 1) LIKE '%*%'
                         OR split_part(substr(pattern, strpos(pattern, '://') + 3), '/', 1) = ''))))
       OR (target_type = 'host'
           AND (pattern LIKE '%/%'
                OR pattern ~ '^[0-9a-fA-F:.]+-[0-9a-fA-F:.]+$'
                OR (pattern LIKE '%*%' AND pattern !~ '^\*\.[^*]+$')
                OR pattern ~ '^\*\*?\.[^.*]+\.?$'))
     )
), taken AS (
    UPDATE scope_targets st
       SET status = h.new_status, updated_at = now()
      FROM hit h
     WHERE st.id = h.id AND st.tenant_id = h.tenant_id
    RETURNING st.id
)
INSERT INTO audit_logs (tenant_id, action, resource_type, resource_id, resource_name, changes, severity, message, metadata)
SELECT tenant_id, 'scope_target.deactivated', 'scope_target', id::text, left(pattern, 500),
       jsonb_build_object('status', jsonb_build_object('old', old_status, 'new', new_status)),
       'medium',
       format('Scope entry (%s) taken out of effect: its pattern could cover every host or address', target_type),
       jsonb_build_object('source', 'migration', 'trigger', 'scope_wildcard_entries', 'target_type', target_type)
  FROM hit;
