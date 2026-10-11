-- A pull request merged into the default branch without a passing CI gate
-- verdict (RFC-077 section 4).
INSERT INTO event_types (id, name, description, category, module_id, is_active, metadata, created_at)
VALUES ('ci.ungated_merge', 'CI ungated merge', 'A pull request was merged into the default branch without a passing CI gate verdict', 'sensor', 'scans', true, '{}', NOW())
ON CONFLICT (id) DO NOTHING;
