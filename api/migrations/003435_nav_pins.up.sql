-- nav_pins (up): the items a member pins to the top of the sidebar, per
-- organization (research/236 C4). A pin names a page path, a built-in
-- findings quick view or a saved view; the API re-checks a saved view's
-- visibility on every read, so a pin never grants access.
CREATE TABLE IF NOT EXISTS nav_pins (
    id         uuid        PRIMARY KEY DEFAULT uuid_generate_v7(),
    tenant_id  uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       text        NOT NULL,
    ref        text        NOT NULL,
    position   smallint    NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_nav_pins_kind CHECK (kind IN ('page', 'quick_view', 'saved_view')),
    CONSTRAINT chk_nav_pins_ref CHECK (char_length(ref) BETWEEN 1 AND 200),
    CONSTRAINT chk_nav_pins_position CHECK (position BETWEEN 0 AND 99),
    CONSTRAINT uq_nav_pins_ref UNIQUE (tenant_id, user_id, kind, ref)
);

CREATE INDEX IF NOT EXISTS idx_nav_pins_user ON nav_pins (tenant_id, user_id, position);

COMMENT ON TABLE nav_pins IS 'Sidebar pins of a member in one organization: a page, a findings quick view or a saved view';
