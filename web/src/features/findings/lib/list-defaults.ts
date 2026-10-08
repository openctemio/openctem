/**
 * Statuses the Findings list hides unless a status filter is set: pentest work
 * in progress that is not ready to be seen. Anything that links to the list
 * with a count (e.g. "View 12 findings") must leave these out of the count too,
 * or the number on the link will not match the list it opens.
 */
export const FINDINGS_LIST_HIDDEN_STATUSES = ['draft', 'in_review'] as const

/**
 * The Findings list's "Open" status group: what an "open findings" link
 * filters on. Kept under the API's 10-status cap for `statuses`.
 */
export const FINDINGS_OPEN_STATUSES = [
  'new',
  'confirmed',
  'in_progress',
  'fix_applied',
  'validated_fixed', // validation no longer observes it; a person still closes it
  'not_observed', // stale, not fixed: still open
] as const
