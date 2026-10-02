-- User In-App Notification System
-- Fan-out on read architecture with watermark for scalable notifications

-- Table 1: notifications (shared, 1 row per event)
CREATE TABLE IF NOT EXISTS notifications (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    audience          VARCHAR(10) NOT NULL DEFAULT 'all',
    audience_id       UUID,
    notification_type VARCHAR(50) NOT NULL,
    title             VARCHAR(500) NOT NULL,
    body              TEXT,
    severity          VARCHAR(20) NOT NULL DEFAULT 'info',
    resource_type     VARCHAR(50),
    resource_id       UUID,
    url               VARCHAR(1000),
    actor_id          UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_notification_audience CHECK (audience IN ('all', 'group', 'user')),
    CONSTRAINT chk_notification_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    CONSTRAINT chk_notification_audience_id CHECK (
        (audience = 'all' AND audience_id IS NULL) OR
        (audience IN ('group', 'user') AND audience_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_notifications_tenant_feed ON notifications (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_audience ON notifications (tenant_id, audience, audience_id, created_at DESC) WHERE audience != 'all';

-- Table 2: notification_reads (sparse, individual reads after watermark)
CREATE TABLE IF NOT EXISTS notification_reads (
    notification_id UUID NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    read_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (notification_id, user_id)
);

-- Table 3: notification_state (watermark, 1 per user)
CREATE TABLE IF NOT EXISTS notification_state (
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    last_read_all_at TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01',
    PRIMARY KEY (tenant_id, user_id)
);

-- Table 4: notification_preferences (1 per user)
CREATE TABLE IF NOT EXISTS notification_preferences (
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    in_app_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    email_digest VARCHAR(20) NOT NULL DEFAULT 'none',
    muted_types  JSONB,
    min_severity VARCHAR(20),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id)
);
