/**
 * Leaving a page after the session changed: sign-in, an organization joined,
 * created, selected, left or deleted, a second factor completed.
 *
 * The session lives in httpOnly cookies the server just set. A client-side
 * navigation (router.push) keeps this document: its auth store, its
 * organization context, its data caches and the router's cache of rendered
 * pages all still describe the previous session, so the person can land in
 * the previous organization, or be sent on by a page that reads the old
 * state. A full page load reads the new cookies everywhere at once, so every
 * such navigation goes through `navigateAfterSessionChange`.
 *
 * - The destination is a same-origin path only (never an open redirect: an
 *   absolute or protocol-relative URL falls back to `/`).
 * - The invitation token kept for the tab is forgotten, unless the
 *   destination is the invitation page itself (sign-in from an invitation
 *   returns there).
 * - A message for the person ("You joined Acme") would be lost with the
 *   document, so it is kept for the next page as a one-time flash in this
 *   tab's sessionStorage and shown by the app's toaster once it loads
 *   (`takeSessionFlash`, src/components/app-toaster.tsx).
 */

import { validateRedirectUrl } from '@/lib/redirect'
import { INVITATION_PAGE, clearInvitationToken } from '@/features/auth/lib/invitation-token'

export type SessionFlashKind = 'success' | 'info'

/** A message shown once on the next page of this tab. */
export interface SessionFlash {
  kind: SessionFlashKind
  title: string
  description?: string
}

const FLASH_KEY = 'openctem.session-flash'
/** Long enough for any sentence the console writes; bounds what is kept. */
const MAX_TEXT = 300

/**
 * The page to load: a same-origin path (with its query), else `fallback`.
 * Only a path that starts with a single `/` is accepted.
 */
export function sessionLandingPath(path: string | null | undefined, fallback = '/'): string {
  if (typeof path !== 'string' || !path.startsWith('/')) return fallback
  const safe = validateRedirectUrl(path, fallback)
  return safe.startsWith('/') && !/^\/[/\\]/.test(safe) ? safe : fallback
}

function pathOnly(url: string): string {
  const cut = url.search(/[?#]/)
  return cut < 0 ? url : url.slice(0, cut)
}

/** Keeps a message for the next page of this tab. */
export function stashSessionFlash(flash: SessionFlash): void {
  try {
    window.sessionStorage.setItem(
      FLASH_KEY,
      JSON.stringify({
        kind: flash.kind,
        title: flash.title.slice(0, MAX_TEXT),
        ...(flash.description ? { description: flash.description.slice(0, MAX_TEXT) } : {}),
      })
    )
  } catch {
    // Storage unavailable: the page still opens, without the message.
  }
}

/** The message kept for this page, removed as it is read (shown once). */
export function takeSessionFlash(): SessionFlash | null {
  if (typeof window === 'undefined') return null
  let raw: string | null = null
  try {
    raw = window.sessionStorage.getItem(FLASH_KEY)
    if (raw !== null) window.sessionStorage.removeItem(FLASH_KEY)
  } catch {
    return null
  }
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw) as Partial<SessionFlash>
    if (parsed.kind !== 'success' && parsed.kind !== 'info') return null
    if (typeof parsed.title !== 'string' || !parsed.title) return null
    return {
      kind: parsed.kind,
      title: parsed.title.slice(0, MAX_TEXT),
      ...(typeof parsed.description === 'string' && parsed.description
        ? { description: parsed.description.slice(0, MAX_TEXT) }
        : {}),
    }
  } catch {
    return null
  }
}

export interface SessionNavigationOptions {
  /** Shown once on the page that loads. */
  flash?: SessionFlash
  /** Replace this page in the history (Back does not return to it). */
  replace?: boolean
}

/**
 * Loads `path` (a same-origin path; `/` opens the active organization's
 * home) as a new document, so the session cookies just set are read by
 * everything on it.
 */
export function navigateAfterSessionChange(
  path: string = '/',
  options: SessionNavigationOptions = {}
): void {
  if (typeof window === 'undefined') return
  const target = sessionLandingPath(path)
  if (pathOnly(target) !== INVITATION_PAGE) clearInvitationToken()
  if (options.flash) stashSessionFlash(options.flash)
  if (options.replace) window.location.replace(target)
  else window.location.assign(target)
}
