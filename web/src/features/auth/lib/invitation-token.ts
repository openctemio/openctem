/**
 * Where the invitation token lives in the browser.
 *
 * The token is a bearer credential, so it stays out of every URL the server or
 * a proxy can see (RFC-041, api/docs/rfcs/RFC-041-api-path-design.md):
 *
 * - Emailed links are `/invitations#token=…`. A fragment is never sent to a
 *   server and never appears in a Referer header.
 * - Older links (`/invitations/{token}`) still work: that page hands the token
 *   over and replaces the URL with `/invitations`.
 * - On landing the token moves to this tab's sessionStorage and the fragment is
 *   removed with history.replaceState, so it is not kept in the history and
 *   survives the trip to /login or /register and back (`returnTo=/invitations`).
 * - API calls send it in the request body.
 *
 * sessionStorage is per tab and cleared when the tab closes. It can be
 * unavailable (private mode, blocked storage): then the token simply is not
 * kept, and the invitation link has to be opened again after signing in.
 */

/** The invitation page. */
export const INVITATION_PAGE = '/invitations'

const STORAGE_KEY = 'openctem.invitation-token'

/** Tokens are 43 base64url characters; allow older formats, refuse junk. */
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{20,100}$/

/** The invitation link for a token (the fragment form). */
export function invitationLink(origin: string, token: string): string {
  return `${origin.replace(/\/+$/, '')}${INVITATION_PAGE}#token=${encodeURIComponent(token)}`
}

function validToken(token: string | null | undefined): token is string {
  return typeof token === 'string' && TOKEN_SHAPE.test(token)
}

/** Keeps the token for this tab. */
export function stashInvitationToken(token: string): void {
  if (!validToken(token)) return
  try {
    window.sessionStorage.setItem(STORAGE_KEY, token)
  } catch {
    // Storage unavailable: the page still works for this visit.
  }
}

/** The token kept for this tab, if any. */
export function readStashedInvitationToken(): string | undefined {
  if (typeof window === 'undefined') return undefined
  try {
    const token = window.sessionStorage.getItem(STORAGE_KEY)
    return validToken(token) ? token : undefined
  } catch {
    return undefined
  }
}

/** Forgets the token (after accept or decline). */
export function clearInvitationToken(): void {
  try {
    window.sessionStorage.removeItem(STORAGE_KEY)
  } catch {
    // nothing kept
  }
}

/**
 * The token for the invitation page: taken from the URL fragment when the
 * visitor arrives from a link (then kept for the tab and removed from the
 * address bar and history), otherwise the one kept for this tab.
 */
export function takeInvitationToken(): string | undefined {
  if (typeof window === 'undefined') return undefined
  const hash = window.location.hash.replace(/^#/, '')
  if (hash) {
    const fromHash = new URLSearchParams(hash).get('token')
    if (fromHash !== null) {
      // Drop the fragment whatever it held: it is never shown again.
      window.history.replaceState(
        window.history.state,
        '',
        window.location.pathname + window.location.search
      )
      if (validToken(fromHash)) {
        stashInvitationToken(fromHash)
        return fromHash
      }
      return undefined
    }
  }
  return readStashedInvitationToken()
}
