/**
 * The CRITICALITY scale (business importance): the one source for its values,
 * order and labels. Colors live beside it in criticality-colors.ts.
 *
 * Two lists, because two kinds of record carry a criticality:
 * - ASSET_CRITICALITY_LEVELS: assets (and repositories, which are assets) may
 *   also be `none` = "Not rated". Risk scoring gives none 0 criticality points;
 *   new assets default to medium, so none is always an explicit choice.
 * - RATED_CRITICALITY_LEVELS: asset groups, business units and business
 *   services are always rated (their API has no none).
 *
 * Criticality is a different scale from finding SEVERITY (severity.ts): low
 * criticality is GOOD and green. `src/lib/__tests__/scale-guard.test.ts` fails
 * on a new hard-coded list.
 */

/** Asset criticality, most important first; Not rated last. */
export const ASSET_CRITICALITY_LEVELS = ['critical', 'high', 'medium', 'low', 'none'] as const
export type CriticalityLevel = (typeof ASSET_CRITICALITY_LEVELS)[number]

/** Criticality of records that are always rated (groups, units, services). */
export const RATED_CRITICALITY_LEVELS = ['critical', 'high', 'medium', 'low'] as const
export type RatedCriticality = (typeof RATED_CRITICALITY_LEVELS)[number]

/** The default for a new asset. */
export const DEFAULT_ASSET_CRITICALITY: CriticalityLevel = 'medium'

/** English labels, for code outside React. */
export const CRITICALITY_LABELS: Record<CriticalityLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  none: 'Not rated',
}

/** One-line meaning of each level, for pickers. */
export const CRITICALITY_DESCRIPTIONS: Record<CriticalityLevel, string> = {
  critical: 'Mission-critical asset essential to business operations',
  high: 'Important asset with significant business impact',
  medium: 'Standard asset with moderate business impact',
  low: 'Non-critical asset with minimal business impact',
  none: 'Not rated yet: adds no criticality weight to risk',
}

/** i18n keys of the labels (en/vi catalogs). */
export const CRITICALITY_LABEL_KEYS: Record<CriticalityLevel, string> = {
  critical: 'criticality.critical',
  high: 'criticality.high',
  medium: 'criticality.medium',
  low: 'criticality.low',
  none: 'criticality.none',
}

const RANK: Record<CriticalityLevel, number> = { critical: 0, high: 1, medium: 2, low: 3, none: 4 }

/** Maps a raw API value to the scale (lower-cased); undefined when unknown. */
export function normalizeCriticality(raw: unknown): CriticalityLevel | undefined {
  if (typeof raw !== 'string') return undefined
  const s = raw.trim().toLowerCase()
  return Object.hasOwn(RANK, s) ? (s as CriticalityLevel) : undefined
}

/** Picker options ({ value, label, description }) for a criticality select. */
export function criticalityOptions<T extends CriticalityLevel>(levels: readonly T[]) {
  return levels.map((value) => ({
    value,
    label: CRITICALITY_LABELS[value],
    description: CRITICALITY_DESCRIPTIONS[value],
  }))
}

/** 0 = critical … 4 = not rated; unknown values sort last. */
export function criticalityRank(raw: unknown): number {
  const c = normalizeCriticality(raw)
  return c === undefined ? ASSET_CRITICALITY_LEVELS.length : RANK[c]
}
