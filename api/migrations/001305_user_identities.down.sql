ALTER TABLE users ADD COLUMN federated_issuer text, ADD COLUMN federated_subject text;

-- users holds one binding: keep the most recently used platform-wide identity.
UPDATE users u
SET federated_issuer = i.issuer, federated_subject = i.subject
FROM (
    SELECT DISTINCT ON (user_id) user_id, issuer, subject
    FROM user_identities
    WHERE scope_tenant_id IS NULL
    ORDER BY user_id, COALESCE(last_used_at, created_at) DESC
) i
WHERE u.id = i.user_id;

DROP TABLE user_identities;
