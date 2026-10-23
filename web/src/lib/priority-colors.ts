/**
 * The one colour source for priority classes (P0-P3).
 *
 * Priority is not severity. Severity (critical..info) is a soft badge in the
 * CVSS hues (severity-colors.ts); priority is a filled class box on the brand
 * ink ramp, P0 strongest, so "P1" can never be read as "High". Teal is the
 * act-here accent and is never used for either scale.
 *
 * Every priority surface (badge, chip, chart series, legend, row marker) takes
 * its colour from here, which reads the --prio-* tokens in src/styles/theme.css
 * (checked at AA in both themes by src/styles/__tests__/contrast.test.ts). The
 * palette-drift gate refuses a hand-written priority colour outside this file.
 */

export const PRIORITY_ORDER = ['P0', 'P1', 'P2', 'P3'] as const
export type PriorityClass = (typeof PRIORITY_ORDER)[number]

const BOX = (n: 0 | 1 | 2 | 3) => `bg-prio-${n}-bg text-prio-${n}-fg border-prio-${n}-border`

/** The class box: fill, text and edge. */
export const PRIORITY_BOX_CLASS: Record<PriorityClass, string> = {
  P0: BOX(0),
  P1: BOX(1),
  P2: BOX(2),
  P3: BOX(3),
}

/** Chart series, legend swatches and dots (recharts fill/stroke, inline SVG). */
export const PRIORITY_CHART_COLORS: Record<PriorityClass, string> = {
  P0: 'var(--prio-0)',
  P1: 'var(--prio-1)',
  P2: 'var(--prio-2)',
  P3: 'var(--prio-3)',
}

/** Dot / swatch fill as a class. */
export const PRIORITY_DOT_CLASS: Record<PriorityClass, string> = {
  P0: 'bg-prio-0',
  P1: 'bg-prio-1',
  P2: 'bg-prio-2',
  P3: 'bg-prio-3',
}

/** True for a value that is a priority class. */
export function isPriorityClass(v: unknown): v is PriorityClass {
  return typeof v === 'string' && (PRIORITY_ORDER as readonly string[]).includes(v)
}
