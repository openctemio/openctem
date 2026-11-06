-- A scan workflow's editable draft (the builder's autosave): its steps, the
-- Start/End node positions and the issues the last check found. Saving a
-- draft never fails on a problem in it; publishing makes it the steps runs
-- use, and needs no blocking issue. NULL when there is no draft.

ALTER TABLE scan_workflows
    ADD COLUMN IF NOT EXISTS draft JSONB,
    ADD COLUMN IF NOT EXISTS draft_issues JSONB,
    ADD COLUMN IF NOT EXISTS draft_updated_at TIMESTAMPTZ;
