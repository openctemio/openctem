/**
 * The finding SEVERITY scale: the one source for its values, order and labels.
 * Colors live beside it in severity-colors.ts, keyed by the same type.
 *
 * Every list, filter, facet, summary, chart and mapping that shows severities
 * iterates SEVERITY_LEVELS (or ACTIONABLE_SEVERITIES when it is about
 * remediation deadlines) instead of writing the values out, so info can never
 * be dropped again. `src/lib/__tests__/scale-guard.test.ts` fails on a new
 * hard-coded list.
 *
 * Semantics of info (Informational):
 * - visible and filterable wherever severity appears;
 * - no SLA by default (a policy's info days of 0 = no SLA);
 * - pinned to P3 and no weight in the count-based asset risk;
 * - dashboards count it separately, never inside the open-risk total;
 * - the API stores `none` (CVSS 0.0) too; it is shown as info (normalizeSeverity).
 *
 * Severity is a different scale from asset CRITICALITY (business importance,
 * see criticality.ts): low severity is blue, low criticality is green.
 */

/** Every severity, most severe first. */
export const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'] as const
export type SeverityLevel = (typeof SEVERITY_LEVELS)[number]

/**
 * The severities that carry a remediation obligation by default (an SLA, a
 * place in the open-risk total, an MTTR target). Informational is left out on
 * purpose; show it beside these as its own count.
 */
export const ACTIONABLE_SEVERITIES = SEVERITY_LEVELS.slice(0, 4) as unknown as readonly [
  'critical',
  'high',
  'medium',
  'low',
]
export type ActionableSeverity = (typeof ACTIONABLE_SEVERITIES)[number]

/** English labels, for code outside React (CSV, chart data). */
export const SEVERITY_LABELS: Record<SeverityLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
}

/** The long name of the info level, for headings and dashboard counts. */
export const INFORMATIONAL_LABEL = 'Informational'

/** i18n keys of the labels (en/vi catalogs). */
export const SEVERITY_LABEL_KEYS: Record<SeverityLevel, string> = {
  critical: 'severity.critical',
  high: 'severity.high',
  medium: 'severity.medium',
  low: 'severity.low',
  info: 'severity.info',
}

const RANK: Record<SeverityLevel, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

/**
 * Maps a raw API value to the scale: lower-cased, `none` (CVSS 0.0) folded into
 * info. Returns undefined for an unknown value so callers can show a neutral
 * fallback instead of guessing.
 */
export function normalizeSeverity(raw: unknown): SeverityLevel | undefined {
  if (typeof raw !== 'string') return undefined
  const s = raw.trim().toLowerCase()
  if (s === 'none' || s === 'informational') return 'info'
  return Object.hasOwn(RANK, s) ? (s as SeverityLevel) : undefined
}

/** 0 = critical … 4 = info; unknown values sort after info. */
export function severityRank(raw: unknown): number {
  const s = normalizeSeverity(raw)
  return s === undefined ? SEVERITY_LEVELS.length : RANK[s]
}

/** Array.sort comparator, most severe first. */
export function compareSeverity(a: unknown, b: unknown): number {
  return severityRank(a) - severityRank(b)
}

/** The most severe of the given values (undefined for none known). */
export function highestSeverity(values: Iterable<unknown>): SeverityLevel | undefined {
  let best: SeverityLevel | undefined
  for (const v of values) {
    const s = normalizeSeverity(v)
    if (s !== undefined && (best === undefined || RANK[s] < RANK[best])) best = s
  }
  return best
}

/** True for info and none. */
export function isInformational(raw: unknown): boolean {
  return normalizeSeverity(raw) === 'info'
}

/**
 * Reads a by-severity count map from the API into the scale, folding a
 * separate `none` key into info. Missing keys read as 0.
 */
export function severityCounts(
  by: Partial<Record<string, number>> | null | undefined
): Record<SeverityLevel, number> {
  const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<SeverityLevel, number>
  if (!by) return out
  for (const [k, n] of Object.entries(by)) {
    const s = normalizeSeverity(k)
    if (s !== undefined && typeof n === 'number') out[s] += n
  }
  return out
}

/** Sum of the actionable (critical..low) counts: the open-risk total. */
export function actionableTotal(counts: Partial<Record<SeverityLevel, number>>): number {
  return ACTIONABLE_SEVERITIES.reduce((sum, s) => sum + (counts[s] ?? 0), 0)
}
