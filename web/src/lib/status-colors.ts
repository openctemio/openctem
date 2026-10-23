/**
 * The one colour source for workflow status lozenges.
 *
 * Status colour follows the workflow CATEGORY, not each status: untouched
 * (dashed empty outline), open (grey), in progress (blue), resolved (green),
 * accepted (amber) and closed without a fix (quiet outline). Tokens are the
 * --st-* set in src/styles/theme.css, checked at AA in light and dark by
 * src/styles/__tests__/contrast.test.ts. Severity hues stay with severity,
 * violet with priority and teal with act-here. The palette-drift gate refuses a
 * status colour written outside this file and theme.css.
 */

export const STATUS_TONES = [
  'triage',
  'open',
  'progress',
  'resolved',
  'accepted',
  'closed',
] as const
export type StatusTone = (typeof STATUS_TONES)[number]

/** Lozenge fill, text and edge. Literal classes, so Tailwind generates them. */
export const STATUS_TONE_CLASS: Record<StatusTone, string> = {
  triage: 'bg-st-triage-bg text-st-triage-fg border-st-triage-border border-dashed',
  open: 'bg-st-open-bg text-st-open-fg border-st-open-border',
  progress: 'bg-st-progress-bg text-st-progress-fg border-st-progress-border',
  resolved: 'bg-st-resolved-bg text-st-resolved-fg border-st-resolved-border',
  accepted: 'bg-st-accepted-bg text-st-accepted-fg border-st-accepted-border',
  closed: 'bg-st-closed-bg text-st-closed-fg border-st-closed-border',
}

/** Text colour of a tone, for a glyph drawn on a neutral background. */
export const STATUS_TONE_TEXT: Record<StatusTone, string> = {
  triage: 'text-st-triage-fg',
  open: 'text-st-open-fg',
  progress: 'text-st-progress-fg',
  resolved: 'text-st-resolved-fg',
  accepted: 'text-st-accepted-fg',
  closed: 'text-st-closed-fg',
}
