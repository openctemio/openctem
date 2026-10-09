-- Platform announcements (RFC-022): a short notice from the platform
-- operator, for example planned maintenance, shown to every signed-in user
-- while it is active. Platform-level: no tenant column, plain text only.
CREATE TABLE IF NOT EXISTS platform_announcements (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    message     text NOT NULL CHECK (char_length(message) BETWEEN 1 AND 500),
    severity    text NOT NULL CHECK (severity IN ('info', 'warning', 'maintenance')),
    starts_at   timestamptz NOT NULL DEFAULT now(),
    ends_at     timestamptz,
    created_by  uuid REFERENCES admin_users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_platform_announcements_window CHECK (ends_at IS NULL OR ends_at > starts_at)
);

CREATE INDEX IF NOT EXISTS idx_platform_announcements_window
    ON platform_announcements (starts_at, ends_at);
