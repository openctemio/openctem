/**
 * The findings lists behind the Validation overview (research/370). Each
 * count on the page and the link it opens use the same parameters, so the
 * number a person clicks is the number of rows they land on. Every list is
 * read through the ordinary findings API: the server applies the viewer's
 * tenant and data scope, the page adds nothing of its own.
 */

/** Findings list parameters, sent as they are to the API and to /findings. */
export type FindingsQuery = Record<string, string>

/**
 * Marked fixed, and no re-check has confirmed it yet. With the pentest
 * module on, pentest findings are left out: the retest queue counts them.
 */
export function awaitingValidationQuery(pentestOn: boolean): FindingsQuery {
  return pentestOn
    ? { state: 'open', status: 'fix_applied', source_not: 'pentest' }
    : { state: 'open', status: 'fix_applied' }
}

/** Closed in the last 30 days after a re-check stopped reproducing them. */
export const VALIDATED_RECENTLY: FindingsQuery = {
  state: 'fixed',
  validation: 'not_reproducible',
  resolved_at_gte: '-P30D',
}

/** Open, and the latest re-check reproduced them. */
export const STILL_REPRODUCES: FindingsQuery = { state: 'open', validation: 'reproducible' }

/** Reopened in the last 30 days, whatever their state now. */
export const REOPENED_RECENTLY: FindingsQuery = { state: 'all', last_reopened_at_gte: '-P30D' }

/** The /findings link of a query. */
export function findingsHref(query: FindingsQuery): string {
  return `/findings?${new URLSearchParams(query).toString()}`
}

/**
 * Modules whose work shows on the overview, in display order. Owners can
 * switch each one off; its section then leaves the page.
 */
export const VALIDATION_MODULES = [
  'pentest',
  'attack_simulation',
  'control_testing',
  'mitre_coverage',
] as const

export type ValidationModule = (typeof VALIDATION_MODULES)[number]

/**
 * The validation modules the organization has but switched off: entitled
 * (not missing from its plan) and not enabled. An empty module list means
 * the API reported none, and the console then treats every module as on.
 */
export function switchedOffModules(
  enabledIds: readonly string[],
  notEntitledIds: readonly string[],
  loading: boolean
): ValidationModule[] {
  if (loading || enabledIds.length === 0) return []
  return VALIDATION_MODULES.filter((m) => !enabledIds.includes(m) && !notEntitledIds.includes(m))
}
