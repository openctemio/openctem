-- Scrub the name and email of assignees outside the organization from
-- finding activity history (research doc 21b C2 / research doc 15 L-15).
--
-- Until the assignee membership check (PR #1096), a finding could be
-- assigned to any platform user's id. The assignment activity then stored
-- that user's name and email in the assigning tenant's finding_activities
-- ("assigned": changes.assignee_name / assignee_email; "unassigned":
-- changes.previous_assignee_name). This migration replaces that personal
-- data in the tenant's history, without deleting anything:
--
--   * an "assigned" row whose changes.assignee_id is not a member of the
--     row's tenant: assignee_name becomes a neutral label and assignee_email
--     is removed; assignee_id, the row, its ids and timestamps stay;
--   * an "unassigned" row whose previous assignee (the assignee of the
--     latest earlier "assigned" row on the same finding) is such a user:
--     previous_assignee_name becomes the same label;
--   * message, if it quoted the removed name or email, is cleared.
--
-- Each scrubbed row is marked with changes.assignee_scrubbed = '000923', so
-- the update is idempotent and auditable. "Not a member" means no
-- tenant_members row for (tenant, user), today. A former member who was
-- removed from the organization therefore gets the label too: the label
-- says "not in this organization", which is true, and the id is kept.
--
-- Campaign assignments need nothing here: their audit entries store ids
-- only, never a name or email.
--
-- One-way: the down migration cannot bring the removed text back (it is not
-- kept anywhere, on purpose). That is safe: nothing reads these fields for
-- logic, only for display, and the id still identifies the user.
--
-- The read-only pre-flight that counts the rows this changes is in
-- docs/deployment/safe-deploy-and-migrations.md ("Foreign assignee scrub").

WITH foreign_assigned AS (
    SELECT fa.id
      FROM finding_activities fa
     WHERE fa.activity_type = 'assigned'
       AND fa.changes ? 'assignee_id'
       AND fa.changes->>'assignee_id' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       AND NOT (fa.changes ? 'assignee_scrubbed')
       AND NOT EXISTS (
           SELECT 1 FROM tenant_members m
            WHERE m.tenant_id = fa.tenant_id
              AND m.user_id = (fa.changes->>'assignee_id')::uuid)
), unassigned_prev AS (
    -- The assignee an "unassigned" row refers to: the latest "assigned" row
    -- on the same finding before it.
    SELECT u.id,
           (SELECT a.changes->>'assignee_id'
              FROM finding_activities a
             WHERE a.tenant_id = u.tenant_id AND a.finding_id = u.finding_id
               AND a.activity_type = 'assigned'
               AND (a.created_at, a.id) < (u.created_at, u.id)
             ORDER BY a.created_at DESC, a.id DESC
             LIMIT 1) AS prev_id,
           u.tenant_id
      FROM finding_activities u
     WHERE u.activity_type = 'unassigned'
       AND u.changes ? 'previous_assignee_name'
       AND NOT (u.changes ? 'assignee_scrubbed')
), foreign_unassigned AS (
    SELECT p.id
      FROM unassigned_prev p
     WHERE p.prev_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       AND NOT EXISTS (
           SELECT 1 FROM tenant_members m
            WHERE m.tenant_id = p.tenant_id AND m.user_id = p.prev_id::uuid)
)
UPDATE finding_activities fa
   SET changes = CASE fa.activity_type
           WHEN 'assigned' THEN
               (fa.changes - 'assignee_email')
               || jsonb_build_object('assignee_name', 'Former assignee (not in this organization)',
                                     'assignee_scrubbed', '000923')
           ELSE
               fa.changes
               || jsonb_build_object('previous_assignee_name', 'Former assignee (not in this organization)',
                                     'assignee_scrubbed', '000923')
       END,
       message = CASE
           WHEN fa.message IS NULL OR fa.message = '' THEN fa.message
           WHEN NULLIF(fa.changes->>'assignee_name', '') IS NOT NULL
                AND position(fa.changes->>'assignee_name' IN fa.message) > 0 THEN NULL
           WHEN NULLIF(fa.changes->>'assignee_email', '') IS NOT NULL
                AND position(fa.changes->>'assignee_email' IN fa.message) > 0 THEN NULL
           WHEN NULLIF(fa.changes->>'previous_assignee_name', '') IS NOT NULL
                AND position(fa.changes->>'previous_assignee_name' IN fa.message) > 0 THEN NULL
           ELSE fa.message
       END
 WHERE fa.id IN (SELECT id FROM foreign_assigned UNION ALL SELECT id FROM foreign_unassigned);
