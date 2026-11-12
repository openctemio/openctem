/**
 * Browser storage that holds one organization's data, dropped when the tab's
 * organization changes (switch, another tab's switch, sign-out).
 *
 * Browser storage outlives a switch of organization, so a value written in
 * one organization (finding ids of a triage queue, the list a finding was
 * opened from, a page address with filters, a custom dashboard id, a draft)
 * must either carry the organization id in its key or be listed here.
 * `__tests__/org-scoped-storage.test.ts` lists every file that touches
 * localStorage or sessionStorage with the reason it is safe; a new file
 * fails the test until it is classified.
 * Rule: web/docs/organization-switch.md.
 */

import { clearFormDrafts } from '@/lib/form-drafts'
import { clearRecentQueries } from '@/features/query/lib/recent'
import { removeStoredPermissions } from '@/lib/permission-storage'
import { clearAllLogoCaches, clearTenantLogoCache } from '@/lib/logo-storage'

/** sessionStorage keys whose value belongs to the organization that wrote it. */
export const ORG_SCOPED_SESSION_KEYS: readonly string[] = [
  // Triage mode's queue: a findings query and the ids decided so far.
  'openctem.findings.triage',
  // The list a finding was opened from: query and ordered ids.
  'openctem.findings.listContext',
  // "Back to app" from settings: a page address with its query.
  'openctem:settings-return-to',
]

/** localStorage keys whose value belongs to the organization that wrote it. */
export const ORG_SCOPED_LOCAL_KEYS: readonly string[] = [
  // The viewer's last dashboard: a custom dashboard id of that organization.
  'openctem:dashboard-choice',
]

function removeAll(store: () => Storage, keys: readonly string[]): void {
  try {
    const s = store()
    for (const k of keys) s.removeItem(k)
  } catch {
    // Storage unavailable (private mode, blocked site data): nothing kept.
  }
}

/** Drops the previous organization's browser state. */
export function clearOrgScopedClientState(previousTenantId: string | null | undefined): void {
  if (typeof window === 'undefined') return
  if (previousTenantId) {
    removeStoredPermissions(previousTenantId)
    clearTenantLogoCache(previousTenantId)
  }
  clearAllLogoCaches()
  // Drafts and recent queries belong to the organization they were written in.
  clearFormDrafts()
  clearRecentQueries()
  removeAll(() => window.sessionStorage, ORG_SCOPED_SESSION_KEYS)
  removeAll(() => window.localStorage, ORG_SCOPED_LOCAL_KEYS)
}
