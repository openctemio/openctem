/**
 * The one colour map for SLA state pills (on track, warning, overdue,
 * exceeded, not applicable). State tokens only: green on track, amber warning,
 * red when late. They are state, not severity or priority, and the pill always
 * carries its label.
 */

export type SlaState = 'on_track' | 'warning' | 'overdue' | 'exceeded' | 'not_applicable'

export const SLA_STATE_CLASS: Record<SlaState, string> = {
  // A 5% tint: the success text on a 10% tint was 4.4:1, under WCAG AA.
  on_track: 'border-success/30 bg-success/5 text-success',
  warning: 'border-warning/40 bg-warning/10 text-warning',
  overdue: 'border-destructive/30 bg-destructive/10 text-destructive',
  exceeded: 'border-destructive/50 bg-destructive/15 text-destructive font-semibold',
  not_applicable: 'border-border bg-muted text-muted-foreground',
}

/** The class of a state value from the API; unknown values read as not applicable. */
export function slaStateClass(status: string | null | undefined): string {
  const key = (status ?? '').toLowerCase() as SlaState
  return SLA_STATE_CLASS[key] ?? SLA_STATE_CLASS.not_applicable
}
