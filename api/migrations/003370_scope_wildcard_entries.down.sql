-- Put back the status the up migration changed, from its audit events. An
-- entry someone has since removed stays removed; one a person changed by hand
-- afterwards is set back too, so read the audit log before reverting.
UPDATE scope_targets st
   SET status = al.changes -> 'status' ->> 'old', updated_at = now()
  FROM audit_logs al
 WHERE al.resource_type = 'scope_target'
   AND al.resource_id = st.id::text
   AND al.tenant_id = st.tenant_id
   AND al.metadata ->> 'trigger' = 'scope_wildcard_entries'
   AND st.status IN ('inactive', 'rejected');
