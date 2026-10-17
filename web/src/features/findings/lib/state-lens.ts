/**
 * The findings state lens (research 24 §2.2, owner decision C2): Open ·
 * Fixed · Dispositioned · All, Open by default. It is one URL param, `state`,
 * which the API compiles to a status set, so the list, the metric strip, the
 * groups and the export all show the same findings. A disposition (false
 * positive, accepted risk, duplicate) is never counted as fixed.
 */

export type FindingLens = 'open' | 'fixed' | 'dispositioned' | 'all'

export const DEFAULT_FINDING_LENS: FindingLens = 'open'

/**
 * The lenses, Open first. `label` and `description` are the English
 * fallbacks of the i18n keys `findings.lens.<value>.label` and
 * `findings.lens.<value>.description` (lensLabelKey / lensDescriptionKey).
 */
export const FINDING_LENSES: { value: FindingLens; label: string; description: string }[] = [
  { value: 'open', label: 'Open', description: 'Findings that still need work' },
  { value: 'fixed', label: 'Fixed', description: 'Resolved and verified fixes' },
  {
    value: 'dispositioned',
    label: 'Dispositioned',
    description: 'False positives, accepted risks and duplicates (never counted as fixed)',
  },
  { value: 'all', label: 'All', description: 'Every finding' },
]

/** The i18n key of a lens's label. */
export const lensLabelKey = (lens: FindingLens) => `findings.lens.${lens}.label`

/** The i18n key of a lens's description. */
export const lensDescriptionKey = (lens: FindingLens) => `findings.lens.${lens}.description`

/** The lens a URL value names, or the default for anything else. */
export function parseFindingLens(raw: string | null | undefined): FindingLens {
  return FINDING_LENSES.some((l) => l.value === raw) ? (raw as FindingLens) : DEFAULT_FINDING_LENS
}
