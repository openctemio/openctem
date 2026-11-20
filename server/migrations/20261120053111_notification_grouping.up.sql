-- Grouped channel notifications (docs/architecture/notification-system.md,
-- "Grouped alerts").
--
-- Events of the same kind about findings that reach the same channel within
-- a short window are delivered as one message. Every event keeps its own
-- outbox row and archive entry; only the delivery is grouped.
--
-- integration_notification_extensions gains the per-channel settings:
--   group_similar         group similar alerts (on by default, also for
--                         existing channels)
--   group_window_minutes  how long a group collects before it is sent
--   urgent_at_once        a critical or known-exploited item is sent on its
--                         own at once instead of waiting for the group
--
-- notification_groups: one row per group of one channel and one event type.
-- At most one group per channel and event type is open; a closed group is
-- the record of what one grouped message carried.
--
-- notification_group_items: one row per object (finding) of a group, with
-- the copy of its latest event (a flap of the same finding updates the row,
-- update_count counts the events folded into it).
--
-- Live impact: three columns with constant defaults (no table rewrite) and
-- two new empty tables.

ALTER TABLE integration_notification_extensions
    ADD COLUMN IF NOT EXISTS group_similar boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS group_window_minutes integer NOT NULL DEFAULT 2,
    ADD COLUMN IF NOT EXISTS urgent_at_once boolean NOT NULL DEFAULT true;

ALTER TABLE integration_notification_extensions
    DROP CONSTRAINT IF EXISTS chk_integration_notification_group_window;
ALTER TABLE integration_notification_extensions
    ADD CONSTRAINT chk_integration_notification_group_window
    CHECK (group_window_minutes BETWEEN 1 AND 60);

COMMENT ON COLUMN integration_notification_extensions.group_similar IS
    'Similar alerts (same event type, about findings) arriving within the window reach this channel as one message.';
COMMENT ON COLUMN integration_notification_extensions.group_window_minutes IS
    'Minutes a group collects alerts before it is sent (1 to 60).';
COMMENT ON COLUMN integration_notification_extensions.urgent_at_once IS
    'A critical or known-exploited alert is sent on its own at once (a few per window), the rest are grouped.';

CREATE TABLE IF NOT EXISTS notification_groups (
    id             uuid         NOT NULL DEFAULT uuid_generate_v7(),
    tenant_id      uuid         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    integration_id uuid         NOT NULL REFERENCES integrations (id) ON DELETE CASCADE,
    group_key      varchar(100) NOT NULL,
    status         varchar(16)  NOT NULL DEFAULT 'open',
    burst          boolean      NOT NULL DEFAULT false,
    item_count     integer      NOT NULL DEFAULT 0,
    urgent_sent    integer      NOT NULL DEFAULT 0,
    opened_at      timestamptz  NOT NULL DEFAULT now(),
    last_item_at   timestamptz  NOT NULL DEFAULT now(),
    flush_at       timestamptz  NOT NULL,
    closed_at      timestamptz,
    sent_count     integer      NOT NULL DEFAULT 0,
    outbox_id      uuid,
    CONSTRAINT pk_notification_groups PRIMARY KEY (id),
    CONSTRAINT chk_notification_groups_status CHECK (status IN ('open', 'closed')),
    CONSTRAINT chk_notification_groups_closed CHECK ((status = 'open') = (closed_at IS NULL)),
    CONSTRAINT chk_notification_groups_counts CHECK (item_count >= 0 AND urgent_sent >= 0 AND sent_count >= 0)
);

COMMENT ON TABLE notification_groups IS
    'Groups of similar alerts for one channel: open while collecting, closed once handed to the outbox as one message (outbox_id) or found empty.';
COMMENT ON COLUMN notification_groups.burst IS
    'Opened right after another group of the same channel and kind was sent: collects until the burst is quiet (no early send at the item limit).';
COMMENT ON COLUMN notification_groups.sent_count IS
    'Items the grouped message announced (items sent alone or undone since are left out).';

-- One open group per channel and kind.
CREATE UNIQUE INDEX IF NOT EXISTS ux_notification_groups_open
    ON notification_groups (tenant_id, integration_id, group_key) WHERE status = 'open';
-- The claim scans the open groups.
CREATE INDEX IF NOT EXISTS ix_notification_groups_due
    ON notification_groups (flush_at) WHERE status = 'open';
-- The burst check reads the latest closed group of a channel and kind;
-- retention deletes closed groups by age.
CREATE INDEX IF NOT EXISTS ix_notification_groups_recent
    ON notification_groups (tenant_id, integration_id, group_key, closed_at DESC) WHERE status = 'closed';
CREATE INDEX IF NOT EXISTS ix_notification_groups_closed_at
    ON notification_groups (closed_at) WHERE status = 'closed';
CREATE INDEX IF NOT EXISTS ix_notification_groups_integration
    ON notification_groups (integration_id);

CREATE TABLE IF NOT EXISTS notification_group_items (
    group_id       uuid          NOT NULL REFERENCES notification_groups (id) ON DELETE CASCADE,
    tenant_id      uuid          NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    item_key       varchar(100)  NOT NULL,
    outbox_id      uuid          NOT NULL,
    event_type     varchar(100)  NOT NULL,
    aggregate_type varchar(100)  NOT NULL,
    aggregate_id   uuid,
    title          varchar(500)  NOT NULL DEFAULT '',
    body           text          NOT NULL DEFAULT '',
    severity       varchar(20)   NOT NULL DEFAULT 'info',
    url            varchar(2000) NOT NULL DEFAULT '',
    metadata       jsonb         NOT NULL DEFAULT '{}'::jsonb,
    urgent         boolean       NOT NULL DEFAULT false,
    sent_alone     boolean       NOT NULL DEFAULT false,
    update_count   integer       NOT NULL DEFAULT 1,
    event_at       timestamptz   NOT NULL,
    added_at       timestamptz   NOT NULL DEFAULT now(),
    updated_at     timestamptz   NOT NULL DEFAULT now(),
    CONSTRAINT pk_notification_group_items PRIMARY KEY (group_id, item_key),
    CONSTRAINT chk_notification_group_items_metadata CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT chk_notification_group_items_updates CHECK (update_count >= 1)
);

COMMENT ON TABLE notification_group_items IS
    'The objects of a notification group, each with a copy of its latest event; a repeated event about the same object updates its row.';
COMMENT ON COLUMN notification_group_items.sent_alone IS
    'An urgent item delivered on its own at once; recorded in the group, left out of the grouped message.';

-- The findings list filter notification_group_id reads a group's items by
-- tenant.
CREATE INDEX IF NOT EXISTS ix_notification_group_items_tenant_group
    ON notification_group_items (tenant_id, group_id);
