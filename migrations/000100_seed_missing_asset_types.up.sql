-- Seed missing asset types that exist in Go code but not in DB
-- These types are used by the API and UI but missing from the asset_types table,
-- causing FK constraint violations when creating assets of these types.

INSERT INTO asset_types (code, name, description, is_system, is_active, display_order)
VALUES
    ('ip_address', 'IP Address', 'IPv4/IPv6 addresses', TRUE, TRUE, 14),
    ('serverless', 'Serverless', 'Serverless functions (Lambda, Cloud Functions)', TRUE, TRUE, 34),
    ('iam_user', 'IAM User', 'Cloud IAM user accounts', TRUE, TRUE, 40),
    ('iam_role', 'IAM Role', 'Cloud IAM roles and policies', TRUE, TRUE, 41),
    ('service_account', 'Service Account', 'Service accounts and machine identities', TRUE, TRUE, 42)
ON CONFLICT (code) DO NOTHING;
