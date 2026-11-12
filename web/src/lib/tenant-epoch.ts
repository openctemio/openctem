/**
 * The organization epoch of this tab: what a switch of organization ends.
 *
 * Everything the console shows belongs to the organization of the session
 * (the server reads it from the access token). When the organization changes,
 * by the switcher in this tab or in another tab of the same browser, nothing
 * of the previous one may stay: not its data, not its ids in the address, not
 * a request still in flight. The pieces:
 *
 * - `setActiveTenantId` records the organization this tab renders. Every
 *   request of the API client goes through `tenantRequestSignal`, which
 *   refuses to send it when the session cookie names another organization
 *   (another tab switched): the tab is reset first, so no request built from
 *   the old organization's state (a selection of its ids, a filter) is sent
 *   under the new session.
 * - `endTenantEpoch` aborts the reads still in flight; their answers belong
 *   to the old organization.
 * - `announceTenantSwitch` / `onTenantChangedElsewhere` tell the other tabs.
 * - `noteRendered` / `renderedUnderOtherOrg` remember which organization each
 *   address of the tab was shown in, so the back button cannot reopen the
 *   old organization's page (src/components/layout/tenant-epoch-boundary.tsx).
 *
 * The React side (remounting the whole dashboard tree with a fresh data
 * cache, the landing page) is TenantProvider + TenantEpochBoundary.
 * Rule and rationale: web/docs/organization-switch.md.
 */

import { env } from '@/lib/env'
import { resetRequestDedupe } from '@/lib/api/request-dedupe'

/** Thrown instead of sending a request after the organization changed. */
export class TenantChangedError extends Error {
  readonly code = 'TENANT_CHANGED'
  constructor() {
    super('The organization changed; the request was not sent.')
    this.name = 'TenantChangedError'
  }
}

/** Window event: this tab learned that the session's organization changed. */
export const TENANT_CHANGED_EVENT = 'openctem:tenant-changed'

const CHANNEL_NAME = 'openctem:tenant'

let activeTenantId: string | null = null
let epochController = new AbortController()

/** The organization this tab renders (null before the first read). */
export function setActiveTenantId(id: string | null): void {
  activeTenantId = id
}

export function getActiveTenantId(): string | null {
  return activeTenantId
}

/** The organization id the session cookie names, or null. */
export function readTenantCookieId(): string | null {
  if (typeof document === 'undefined') return null
  const name = env.cookies.tenant
  for (const part of document.cookie.split(';')) {
    const eq = part.indexOf('=')
    if (eq < 0 || part.slice(0, eq).trim() !== name) continue
    try {
      const parsed = JSON.parse(decodeURIComponent(part.slice(eq + 1).trim())) as {
        id?: unknown
      }
      return typeof parsed.id === 'string' && parsed.id ? parsed.id : null
    } catch {
      return null
    }
  }
  return null
}

/**
 * The organization the session moved to when it is not the one this tab
 * renders, else null. A missing cookie is not a change: the server refuses
 * such requests on its own.
 */
export function tenantChangedTo(): string | null {
  if (!activeTenantId) return null
  const cookieId = readTenantCookieId()
  return cookieId && cookieId !== activeTenantId ? cookieId : null
}

function notifyChanged(): void {
  if (typeof window !== 'undefined') window.dispatchEvent(new Event(TENANT_CHANGED_EVENT))
}

/**
 * Called by the API client before every browser request. Throws
 * TenantChangedError (and starts the tab's reset) when the session now
 * belongs to another organization. Returns the signal that ends reads with
 * the epoch; writes are not tied to it (a write already sent completes on
 * the server either way, and its caller should learn the outcome).
 */
export function tenantRequestSignal(method: string): AbortSignal | undefined {
  if (tenantChangedTo()) {
    notifyChanged()
    throw new TenantChangedError()
  }
  const m = method.toUpperCase()
  return m === 'GET' || m === 'HEAD' ? epochController.signal : undefined
}

/**
 * Aborts every read of the ending epoch and forgets the GETs in flight, so a
 * read of the new organization never joins one the old organization started
 * (the API client coalesces identical GETs by URL).
 */
export function endTenantEpoch(): void {
  epochController.abort(new TenantChangedError())
  epochController = new AbortController()
  resetRequestDedupe()
}

/** True for the abort of a read that ended with its epoch. */
export function isTenantChangedError(err: unknown): boolean {
  return (
    err instanceof TenantChangedError ||
    (typeof err === 'object' &&
      err !== null &&
      (err as { code?: unknown }).code === 'TENANT_CHANGED')
  )
}

// ----------------------------------------------------------------------------
// Other tabs
// ----------------------------------------------------------------------------

function channel(): BroadcastChannel | null {
  try {
    return typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel(CHANNEL_NAME)
  } catch {
    return null
  }
}

/** Tells the other tabs of this browser that the session switched. */
export function announceTenantSwitch(tenantId: string): void {
  const ch = channel()
  if (!ch) return
  try {
    ch.postMessage({ tenantId })
  } finally {
    ch.close()
  }
}

/**
 * Calls `onChange` when the session's organization is no longer the one this
 * tab renders: another tab announced a switch, the tab comes back into view
 * or focus (or out of the back/forward cache) with another organization in
 * the cookie, or a request was refused
 * by `tenantRequestSignal`. Returns the unsubscribe.
 */
export function onTenantChangedElsewhere(onChange: () => void): () => void {
  if (typeof window === 'undefined') return () => {}
  const check = () => {
    if (tenantChangedTo()) onChange()
  }
  const onVisible = () => {
    if (document.visibilityState === 'visible') check()
  }
  const ch = channel()
  if (ch) ch.onmessage = check
  window.addEventListener(TENANT_CHANGED_EVENT, check)
  window.addEventListener('focus', check)
  // A page the browser restored from its back/forward cache.
  window.addEventListener('pageshow', check)
  document.addEventListener('visibilitychange', onVisible)
  return () => {
    ch?.close()
    window.removeEventListener(TENANT_CHANGED_EVENT, check)
    window.removeEventListener('focus', check)
    window.removeEventListener('pageshow', check)
    document.removeEventListener('visibilitychange', onVisible)
  }
}

// ----------------------------------------------------------------------------
// Addresses shown per organization
// ----------------------------------------------------------------------------

/**
 * Which organization each address of this tab was shown in, so the back
 * button cannot reopen the old organization's page. Kept in sessionStorage
 * (per tab, gone with the tab) so it also covers a back navigation that
 * loads a new document. It holds addresses only, never data.
 */
const VISITS_KEY = 'openctem:org-visits'
/** Most addresses remembered (a tab's history is short; bound the map). */
const MAX_VISITS = 200

function readVisits(): Record<string, string> {
  try {
    const raw = window.sessionStorage.getItem(VISITS_KEY)
    const parsed: unknown = raw ? JSON.parse(raw) : {}
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, string>)
      : {}
  } catch {
    return {}
  }
}

/** Records that `url` (path + search) was shown in organization `tenantId`. */
export function noteRendered(url: string, tenantId: string): void {
  if (typeof window === 'undefined') return
  const visits = readVisits()
  delete visits[url]
  visits[url] = tenantId
  const keys = Object.keys(visits)
  for (const k of keys.slice(0, Math.max(0, keys.length - MAX_VISITS))) delete visits[k]
  try {
    window.sessionStorage.setItem(VISITS_KEY, JSON.stringify(visits))
  } catch {
    // Storage unavailable: the in-document switch still resets the address.
  }
}

/** True when `url` was last shown in another organization than `tenantId`. */
export function renderedUnderOtherOrg(url: string, tenantId: string): boolean {
  if (typeof window === 'undefined') return false
  const seen = readVisits()[url]
  return typeof seen === 'string' && seen !== tenantId
}

/** True when this document was loaded by the browser's back or forward button. */
export function loadedByHistory(): boolean {
  try {
    const nav = performance.getEntriesByType('navigation')[0] as
      PerformanceNavigationTiming | undefined
    return nav?.type === 'back_forward'
  } catch {
    return false
  }
}

/** Test hook: forget the module state. */
export function resetTenantEpochForTests(): void {
  activeTenantId = null
  epochController = new AbortController()
  try {
    window.sessionStorage.removeItem(VISITS_KEY)
  } catch {
    // ignore
  }
}
