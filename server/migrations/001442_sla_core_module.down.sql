-- Make SLA toggleable again. Tenant overrides deleted by the up migration
-- are not restored: SLA stays enabled for every organization.
UPDATE modules SET is_core = FALSE WHERE id = 'sla';
