-- One-way by design: 000923 removed the name and email of assignees outside
-- the organization from finding activity history and kept no copy, so there
-- is nothing to restore. Rows, ids and timestamps were never changed, and the
-- assignee id is still on every row, so leaving the scrubbed text in place on
-- a rollback is safe for the previous release (it only displays these
-- fields). The changes.assignee_scrubbed marker stays as the record of what
-- was done.
SELECT 1;
