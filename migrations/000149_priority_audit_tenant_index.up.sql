-- Migration 000149: Add missing tenant index on priority audit log
CREATE INDEX IF NOT EXISTS idx_priority_audit_tenant
  ON priority_class_audit_log(tenant_id, created_at DESC);
