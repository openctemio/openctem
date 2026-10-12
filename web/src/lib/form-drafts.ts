/**
 * Form drafts autosaved to localStorage.
 *
 * A pentest finding draft holds proof-of-concept detail for one
 * organization. localStorage outlives the session and is shared by everyone
 * using the browser, so drafts are dropped when the session ends (sign-out,
 * expired session) and when the user switches organization. Otherwise the
 * next person to open the form, or the same user in another organization,
 * was offered the draft and could restore it there.
 */

/** New pentest finding form (validation > pentest > findings > new). */
export const PENTEST_FINDING_DRAFT_KEY = 'pentest-finding-draft'

/** New pentest template form (settings > pentest > templates > new). */
export const PENTEST_TEMPLATE_DRAFT_KEY = 'pentest-template-draft'

const DRAFT_KEYS = [PENTEST_FINDING_DRAFT_KEY, PENTEST_TEMPLATE_DRAFT_KEY] as const

/** Removes every autosaved form draft. Never throws. */
export function clearFormDrafts(): void {
  if (typeof window === 'undefined') return
  for (const key of DRAFT_KEYS) {
    try {
      window.localStorage.removeItem(key)
    } catch {
      // Storage unavailable: nothing was saved either.
    }
  }
}
