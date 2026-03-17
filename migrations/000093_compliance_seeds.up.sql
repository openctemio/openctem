-- =============================================
-- Compliance Seeds: Module + Permissions + Events
-- (Framework seed data is in a separate migration)
-- =============================================

-- A. Module Registration
INSERT INTO modules (id, slug, name, description, icon, category, display_order, release_status)
VALUES (
    'compliance', 'compliance', 'Compliance',
    'Compliance framework mapping and control assessments',
    'ClipboardCheck', 'compliance', 31, 'released'
) ON CONFLICT (id) DO NOTHING;

-- B. Permissions (7 new)
INSERT INTO permissions (id, module_id, name, description, is_active)
VALUES
    ('compliance:frameworks:read', 'compliance', 'View Compliance Frameworks', 'View compliance frameworks and controls', TRUE),
    ('compliance:frameworks:write', 'compliance', 'Manage Compliance Frameworks', 'Create custom frameworks', TRUE),
    ('compliance:assessments:read', 'compliance', 'View Compliance Assessments', 'View control assessments', TRUE),
    ('compliance:assessments:write', 'compliance', 'Manage Compliance Assessments', 'Update control assessments', TRUE),
    ('compliance:mappings:read', 'compliance', 'View Compliance Mappings', 'View finding-to-control mappings', TRUE),
    ('compliance:mappings:write', 'compliance', 'Manage Compliance Mappings', 'Create/delete finding-to-control mappings', TRUE),
    ('compliance:reports:read', 'compliance', 'View Compliance Reports', 'View compliance reports', TRUE)
ON CONFLICT (id) DO NOTHING;

-- Role Mappings
-- Owner (all 7)
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000001', 'compliance:frameworks:read'),
    ('00000000-0000-0000-0000-000000000001', 'compliance:frameworks:write'),
    ('00000000-0000-0000-0000-000000000001', 'compliance:assessments:read'),
    ('00000000-0000-0000-0000-000000000001', 'compliance:assessments:write'),
    ('00000000-0000-0000-0000-000000000001', 'compliance:mappings:read'),
    ('00000000-0000-0000-0000-000000000001', 'compliance:mappings:write'),
    ('00000000-0000-0000-0000-000000000001', 'compliance:reports:read')
ON CONFLICT DO NOTHING;

-- Admin (all 7)
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000002', 'compliance:frameworks:read'),
    ('00000000-0000-0000-0000-000000000002', 'compliance:frameworks:write'),
    ('00000000-0000-0000-0000-000000000002', 'compliance:assessments:read'),
    ('00000000-0000-0000-0000-000000000002', 'compliance:assessments:write'),
    ('00000000-0000-0000-0000-000000000002', 'compliance:mappings:read'),
    ('00000000-0000-0000-0000-000000000002', 'compliance:mappings:write'),
    ('00000000-0000-0000-0000-000000000002', 'compliance:reports:read')
ON CONFLICT DO NOTHING;

-- Member (read + write assessments/mappings, no framework write)
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000003', 'compliance:frameworks:read'),
    ('00000000-0000-0000-0000-000000000003', 'compliance:assessments:read'),
    ('00000000-0000-0000-0000-000000000003', 'compliance:assessments:write'),
    ('00000000-0000-0000-0000-000000000003', 'compliance:mappings:read'),
    ('00000000-0000-0000-0000-000000000003', 'compliance:mappings:write'),
    ('00000000-0000-0000-0000-000000000003', 'compliance:reports:read')
ON CONFLICT DO NOTHING;

-- Viewer (read only)
INSERT INTO role_permissions (role_id, permission_id) VALUES
    ('00000000-0000-0000-0000-000000000004', 'compliance:frameworks:read'),
    ('00000000-0000-0000-0000-000000000004', 'compliance:assessments:read'),
    ('00000000-0000-0000-0000-000000000004', 'compliance:mappings:read'),
    ('00000000-0000-0000-0000-000000000004', 'compliance:reports:read')
ON CONFLICT DO NOTHING;

-- C. Event Types
INSERT INTO event_types (id, name, description, category, module_id, default_severity, is_active)
VALUES
    ('compliance_assessment_updated', 'Compliance Assessment Updated', 'Control assessment status changed', 'compliance', 'compliance', 'info', TRUE),
    ('compliance_control_overdue', 'Compliance Control Overdue', 'Control assessment past due date', 'compliance', 'compliance', 'medium', TRUE)
ON CONFLICT (id) DO NOTHING;
