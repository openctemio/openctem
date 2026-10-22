/**
 * Where a dashboard figure opens: the list built from the same filter the
 * figure is counted with, so the list total equals the figure. One table, so
 * a figure and its list cannot drift apart.
 */
export const DRILL = {
  /** Open P0 findings (executive summary `p0_open`). */
  p0Open: '/findings?state=open&priority_class=P0',
  /** Open P1 findings (`p1_open`). */
  p1Open: '/findings?state=open&priority_class=P1',
  /** Open findings past their SLA (`sla_breached`: overdue or exceeded). */
  slaBreached: '/findings?state=open&sla_status=overdue,exceeded',
  /** Validation coverage (`/validation/coverage`). */
  validation: '/validation',
} as const
