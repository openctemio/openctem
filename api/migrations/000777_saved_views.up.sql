-- Saved views (UI style contract D15, research 17 R3, RFC-048 §3.6): a named
-- lens on one list page. It stores the RFC-048 FilterDocument (re-validated
-- on every run, never SQL and never results) plus page state (group-by,
-- columns, density). Personal, or shared with one access group (a team):
-- members of the group may use it, only the owner edits it (decision A1);
-- others duplicate it. A view runs as the person using it (decision A5), so
-- sharing a view shares the query, not anyone's rows.
CREATE TABLE IF NOT EXISTS saved_views (
    id          UUID PRIMARY KEY,
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id    UUID REFERENCES groups(id) ON DELETE SET NULL,
    page        VARCHAR(32) NOT NULL,
    name        VARCHAR(120) NOT NULL,
    description VARCHAR(500),
    filter      JSONB NOT NULL DEFAULT '{}'::jsonb,
    group_by    VARCHAR(32),
    columns     TEXT[],
    density     VARCHAR(16),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_saved_views_page CHECK (page IN ('findings')),
    CONSTRAINT chk_saved_views_name CHECK (length(btrim(name)) > 0),
    CONSTRAINT chk_saved_views_filter_size CHECK (pg_column_size(filter) <= 32768),
    CONSTRAINT chk_saved_views_columns CHECK (cardinality(columns) <= 50)
);

CREATE INDEX IF NOT EXISTS idx_saved_views_owner ON saved_views (tenant_id, owner_id, page);
CREATE INDEX IF NOT EXISTS idx_saved_views_group ON saved_views (tenant_id, group_id, page) WHERE group_id IS NOT NULL;

COMMENT ON TABLE saved_views IS 'Saved list views (D15): a FilterDocument plus page state; personal or shared with one group; runs as the viewer.';
COMMENT ON COLUMN saved_views.filter IS 'RFC-048 FilterDocument, validated on save and again on every run. Never SQL, never results.';
COMMENT ON COLUMN saved_views.group_id IS 'Access group the view is shared with (NULL = personal). Members use it; only the owner edits.';
