/**
 * The one colour source for machine-health labels (HealthStatus): the icon of
 * each state. The text next to it is always the foreground colour, so colour
 * is never the only cue (the icon shape differs per state too). Tokens are the
 * --hl-* set in src/styles/theme.css, checked at 3:1 against the card (WCAG
 * 1.4.11) by src/styles/__tests__/contrast.test.ts. Green means done or
 * healthy, blue in motion, amber needs a person or degraded, red failed or
 * down, grey neutral. Teal is never a health colour.
 */

export const HEALTH_STATES = [
  'ok',
  'run',
  'queued',
  'warn',
  'down',
  'paused',
  'off',
  'unknown',
] as const
export type HealthState = (typeof HEALTH_STATES)[number]

/** Icon colour per state. Literal classes, so Tailwind generates them. */
export const HEALTH_ICON_CLASS: Record<HealthState, string> = {
  ok: 'text-hl-ok',
  run: 'text-hl-run',
  queued: 'text-hl-idle',
  warn: 'text-hl-warn',
  down: 'text-hl-down',
  paused: 'text-hl-idle',
  off: 'text-hl-idle',
  unknown: 'text-hl-idle',
}

/** The quiet states also quiet their text. */
export const HEALTH_TEXT_CLASS: Record<HealthState, string> = {
  ok: 'text-foreground',
  run: 'text-foreground',
  queued: 'text-foreground',
  warn: 'text-foreground',
  down: 'text-foreground',
  paused: 'text-foreground',
  off: 'text-muted-foreground',
  unknown: 'text-muted-foreground',
}
