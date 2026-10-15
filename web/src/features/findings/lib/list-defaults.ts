/**
 * Statuses the Findings list hides unless a status filter is set: pentest work
 * in progress that is not ready to be seen. Anything that links to the list
 * with a count (e.g. "View 12 findings") must leave these out of the count too,
 * or the number on the link will not match the list it opens.
 */
export const FINDINGS_LIST_HIDDEN_STATUSES = ['draft', 'in_review'] as const

/*
 * The one definition of open, fixed and dispositioned findings in the web
 * console, the same sets as the API's (pkg/domain/vulnerability
 * status_sets.go): count, filter and link with these, never with a
 * hand-written list.
 */

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

/** Fixed: closed by a verified fix. */
export const FINDINGS_FIXED_STATUSES = ['resolved'] as const

/** Dispositioned: a decision not to fix; never counted as fixed. */
export const FINDINGS_DISPOSITIONED_STATUSES = ['false_positive', 'accepted', 'duplicate'] as const

/** Closed: fixed or dispositioned. */
export const FINDINGS_CLOSED_STATUSES = [
  ...FINDINGS_FIXED_STATUSES,
  ...FINDINGS_DISPOSITIONED_STATUSES,
] as const
