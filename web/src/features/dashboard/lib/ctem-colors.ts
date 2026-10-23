/**
 * CTEM dashboard color helpers.
 *
 * Single source of truth for the colors the CTEM story cards use, so nothing
 * hardcodes a Tailwind palette class or a raw hex. Priority classes have their own
 * ramp (lib/priority-colors.ts), never the severity hues; health states use the
 * state tokens (success, warning, destructive), never severity.
 */

export { PRIORITY_CHART_COLORS, PRIORITY_ORDER } from '@/lib/priority-colors'

/** Recharts <Tooltip> props that adapt to light/dark via theme tokens. */
export const CHART_TOOLTIP_PROPS = {
  contentStyle: {
    backgroundColor: 'var(--popover)',
    border: '1px solid var(--border)',
    borderRadius: 8,
    fontSize: 12,
    color: 'var(--popover-foreground)',
  },
  labelStyle: { color: 'var(--popover-foreground)' },
  itemStyle: { color: 'var(--popover-foreground)' },
} as const

/**
 * Health state used by the CTEM loop stage stripes and coverage bars. `none`
 * is a figure that is not measured (no denominator, or its read failed): it is
 * neutral grey, never green or amber.
 */
export type CtemState = 'good' | 'warn' | 'crit' | 'none'

export const STATE_STRIPE: Record<CtemState, string> = {
  good: 'bg-success',
  warn: 'bg-warning',
  crit: 'bg-destructive',
  none: 'bg-muted-foreground/30',
}

export const STATE_TEXT: Record<CtemState, string> = {
  good: 'text-success',
  warn: 'text-warning',
  crit: 'text-destructive',
  none: 'text-muted-foreground',
}

export const STATE_BAR: Record<CtemState, string> = {
  good: 'bg-success',
  warn: 'bg-warning',
  crit: 'bg-destructive',
  none: 'bg-muted-foreground/30',
}

/** Soft badge (bg + text + border) per health state, for pass/warn/fail chips. */
export const STATE_BADGE_SOFT: Record<CtemState, string> = {
  good: 'bg-success/10 text-success border-success/30',
  warn: 'bg-warning/10 text-warning border-warning/40',
  crit: 'bg-destructive/10 text-destructive border-destructive/30',
  none: 'bg-muted text-muted-foreground border-border',
}

/** A percentage-coverage value → health state (higher is better). */
export function coverageState(pct: number): CtemState {
  if (pct >= 80) return 'good'
  if (pct >= 40) return 'warn'
  return 'crit'
}

/** An open-count value → health state (lower is better; 0 is good). */
export function openCountState(count: number, warnAt = 1, critAt = 5): CtemState {
  if (count >= critAt) return 'crit'
  if (count >= warnAt) return 'warn'
  return 'good'
}
