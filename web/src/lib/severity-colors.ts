/**
 * Centralized severity color system for OpenCTEM.
 *
 * ALL components must import colors from here instead of defining their own.
 * This ensures consistency across findings, exposures, assets, and charts.
 * The scale itself (values, order, labels) is severity.ts.
 */

import {
  INFORMATIONAL_LABEL,
  SEVERITY_LABELS,
  SEVERITY_LEVELS,
  severityCounts,
  type SeverityLevel,
} from '@/lib/severity'

export type { SeverityLevel }

/** The severity scale, most severe first (alias of SEVERITY_LEVELS). */
export const SEVERITY_ORDER: SeverityLevel[] = [...SEVERITY_LEVELS]

/**
 * Every map below reads the severity tokens in src/styles/theme.css
 * (`--sev-*` marks, `--sev-*-text` text at AA, `--sev-*-ink` text on a solid
 * mark), so light and dark each get their checked values and a theme change
 * is one file. Severity colour is for severity only.
 */
/** Chart colours (recharts fill/stroke, inline SVG): CSS variables. */
export const SEVERITY_CHART_COLORS: Record<SeverityLevel, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  info: 'var(--sev-info)',
}

/** Badge classes, light tint (cards, lists). */
export const SEVERITY_BADGE_LIGHT: Record<SeverityLevel, string> = {
  critical: 'bg-sev-critical/10 text-sev-critical-text border-sev-critical/30',
  high: 'bg-sev-high/10 text-sev-high-text border-sev-high/30',
  medium: 'bg-sev-medium/15 text-sev-medium-text border-sev-medium/40',
  low: 'bg-sev-low/10 text-sev-low-text border-sev-low/30',
  info: 'bg-sev-info/10 text-sev-info-text border-sev-info/30',
}

/** Badge classes, solid (prominent display). */
export const SEVERITY_BADGE_SOLID: Record<SeverityLevel, string> = {
  critical: 'bg-sev-critical text-sev-critical-ink hover:bg-sev-critical/90',
  high: 'bg-sev-high text-sev-high-ink hover:bg-sev-high/90',
  medium: 'bg-sev-medium text-sev-medium-ink hover:bg-sev-medium/90',
  low: 'bg-sev-low text-sev-low-ink hover:bg-sev-low/90',
  info: 'bg-sev-info text-sev-info-ink hover:bg-sev-info/90',
}

/** Badge classes, soft tint (count badges, list pills). */
export const SEVERITY_BADGE_SOFT: Record<SeverityLevel, string> = {
  critical: 'bg-sev-critical/15 text-sev-critical-text border-sev-critical/30',
  high: 'bg-sev-high/15 text-sev-high-text border-sev-high/30',
  medium: 'bg-sev-medium/15 text-sev-medium-text border-sev-medium/40',
  low: 'bg-sev-low/15 text-sev-low-text border-sev-low/30',
  info: 'bg-sev-info/15 text-sev-info-text border-sev-info/30',
}

/** Inline severity text. */
export const SEVERITY_TEXT_COLORS: Record<SeverityLevel, string> = {
  critical: 'text-sev-critical-text',
  high: 'text-sev-high-text',
  medium: 'text-sev-medium-text',
  low: 'text-sev-low-text',
  info: 'text-sev-info-text',
}

/** Dot / indicator fill. */
export const SEVERITY_DOT_COLORS: Record<SeverityLevel, string> = {
  critical: 'bg-sev-critical',
  high: 'bg-sev-high',
  medium: 'bg-sev-medium',
  low: 'bg-sev-low',
  info: 'bg-sev-info',
}

/** Text that reads on the solid fill above. */
export const SEVERITY_SOLID_TEXT: Record<SeverityLevel, string> = {
  critical: 'text-sev-critical-ink',
  high: 'text-sev-high-ink',
  medium: 'text-sev-medium-ink',
  low: 'text-sev-low-ink',
  info: 'text-sev-info-ink',
}

/** Border in the severity hue. */
export const SEVERITY_BORDER_COLORS: Record<SeverityLevel, string> = {
  critical: 'border-sev-critical',
  high: 'border-sev-high',
  medium: 'border-sev-medium',
  low: 'border-sev-low',
  info: 'border-sev-info',
}

/**
 * Chart rows for a by-severity count map from the API, in scale order (none
 * folded into info, zero rows dropped). Info is labelled "Informational".
 */
export function severityChartData(
  by: Partial<Record<string, number>> | null | undefined
): { key: SeverityLevel; name: string; value: number; color: string }[] {
  const counts = severityCounts(by)
  return SEVERITY_LEVELS.filter((s) => counts[s] > 0).map((s) => ({
    key: s,
    name: s === 'info' ? INFORMATIONAL_LABEL : SEVERITY_LABELS[s],
    value: counts[s],
    color: SEVERITY_CHART_COLORS[s],
  }))
}

/** Fill of a `Progress` indicator in the severity hue (a risk-score bar). */
export const SEVERITY_PROGRESS_COLORS: Record<SeverityLevel, string> = {
  critical: '[&>div]:bg-sev-critical',
  high: '[&>div]:bg-sev-high',
  medium: '[&>div]:bg-sev-medium',
  low: '[&>div]:bg-sev-low',
  info: '[&>div]:bg-sev-info',
}

/** SVG stroke in the severity hue (progress rings, sparklines). */
export const SEVERITY_STROKE_COLORS: Record<SeverityLevel, string> = {
  critical: 'stroke-sev-critical',
  high: 'stroke-sev-high',
  medium: 'stroke-sev-medium',
  low: 'stroke-sev-low',
  info: 'stroke-sev-info',
}

/**
 * The soft badge split into its parts, for configs that keep `color` (border),
 * `bgColor` and `textColor` apart. Same tokens as SEVERITY_BADGE_SOFT.
 */
export function severityStyleParts(level: SeverityLevel): {
  color: string
  bgColor: string
  textColor: string
} {
  const tokens = SEVERITY_BADGE_SOFT[level].split(' ')
  const pick = (prefix: string) => tokens.filter((t) => t.startsWith(prefix)).join(' ')
  return { color: pick('border-'), bgColor: pick('bg-'), textColor: pick('text-') }
}
