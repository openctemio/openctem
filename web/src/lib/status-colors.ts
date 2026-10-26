/**
 * The one colour source for workflow status lozenges.
 *
 * Status colour follows the workflow CATEGORY, not each status: untouched
 * (dashed empty outline), open (grey), in progress (blue), waiting on a person
 * (amber, the accepted colours, told apart by its clock icon), resolved (green),
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
  'waiting',
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
  waiting: 'bg-st-waiting-bg text-st-waiting-fg border-st-waiting-border',
  resolved: 'bg-st-resolved-bg text-st-resolved-fg border-st-resolved-border',
  accepted: 'bg-st-accepted-bg text-st-accepted-fg border-st-accepted-border',
  closed: 'bg-st-closed-bg text-st-closed-fg border-st-closed-border',
}

/** Text colour of a tone, for a glyph drawn on a neutral background. */
export const STATUS_TONE_TEXT: Record<StatusTone, string> = {
  triage: 'text-st-triage-fg',
  open: 'text-st-open-fg',
  progress: 'text-st-progress-fg',
  waiting: 'text-st-waiting-fg',
  resolved: 'text-st-resolved-fg',
  accepted: 'text-st-accepted-fg',
  closed: 'text-st-closed-fg',
}

/**
 * Solid fill of a tone, for a segment of a stacked status bar or its legend
 * swatch (the tone's text colour as a background, so it holds AA against the
 * card in both themes). The segment's text label is always beside it.
 */
export const STATUS_TONE_FILL: Record<StatusTone, string> = {
  triage: 'bg-st-triage-border',
  open: 'bg-st-open-fg',
  progress: 'bg-st-progress-fg',
  waiting: 'bg-st-waiting-fg',
  resolved: 'bg-st-resolved-fg',
  accepted: 'bg-st-accepted-fg',
  closed: 'bg-st-closed-fg',
}
