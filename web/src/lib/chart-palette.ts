/**
 * Validated chart palettes for dashboards (source: chart-palette.json, checked
 * by scripts/check-palette.mjs and its vitest twin). Components colour marks
 * with the CSS variables below, so light and dark mode each get their own
 * validated steps without a JS theme lookup. Hex values are exported for the
 * rare place a variable cannot be used (exports, canvas).
 *
 * Rules the kit follows: categorical colours are assigned in fixed order and
 * never cycled (a 9th series folds into "Other"); severity is ordinal and
 * always labelled; status colours (good / warning / critical / unmeasured)
 * are separate tokens and always come with an icon and a label.
 */
import { isPriorityClass, PRIORITY_CHART_COLORS } from '@/lib/priority-colors'
import { SEVERITY_LEVELS, type SeverityLevel } from '@/lib/severity'
import palette from './chart-palette.json'

export const CHART_PALETTE = palette

export type SeverityKey = SeverityLevel

/** CSS colour for a severity mark. */
export function severityVar(key: SeverityKey): string {
  return `var(--viz-sev-${key})`
}

/** Number of categorical slots before the rest folds into "Other". */
export const CATEGORICAL_SLOTS = palette.categorical.light.length

/** CSS colour for the categorical slot at index (0-based); past the last slot: "Other". */
export function categoricalVar(index: number): string {
  if (index < 0 || index >= CATEGORICAL_SLOTS) return 'var(--viz-cat-other)'
  return `var(--viz-cat-${index + 1})`
}

/** CSS colour for one arm of a flow pair (opened vs fixed). */
export function divergingVar(key: 'opened' | 'fixed'): string {
  return `var(--viz-div-${key})`
}

export const SEQUENTIAL_STEPS = palette.sequential.light.length

/** Fill and ink for a sequential step (0 = least). */
export function sequentialStep(step: number): { fill: string; ink: string } {
  const s = Math.max(0, Math.min(SEQUENTIAL_STEPS - 1, step))
  return { fill: `var(--viz-seq-${s + 1})`, ink: `var(--viz-seq-ink-${s + 1})` }
}

const SEVERITY_KEYS = new Set<string>(SEVERITY_LEVELS)
/**
 * The colour of a series by its key: severities and priority classes have
 * their ordinal colour (priority has its own ink ramp, never the severity hues); anything else takes the categorical slot of its
 * position, which the caller keeps stable (colour follows the entity).
 */
export function seriesVar(key: string, index: number): string {
  if (SEVERITY_KEYS.has(key)) return severityVar(key as SeverityKey)
  if (isPriorityClass(key)) return PRIORITY_CHART_COLORS[key]
  if (key === 'opened' || key === 'fixed') return divergingVar(key)
  if (key === 'other') return 'var(--viz-cat-other)'
  return categoricalVar(index)
}
