/**
 * What to show for a finding's assignee. A finding can carry an assignee id
 * before the name has loaded (a list row, or a person who left the team), so
 * "has an assignee" and "has a name" are separate: an id without a name reads
 * "Assigned", never "Unassigned" and never the raw id.
 */
export function assigneeLabel(
  assignee: { name?: string } | null | undefined,
  labels: { assigned: string; unassigned: string }
): string {
  if (!assignee) return labels.unassigned
  return assignee.name?.trim() || labels.assigned
}
