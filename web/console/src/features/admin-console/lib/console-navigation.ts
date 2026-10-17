/**
 * Navigation helpers for the console sign-in pages.
 */

const NEXT_KEY = 'openctem.admin.next'

const CONSOLE_ROOT = '/'
/** Any origin: only used to resolve a relative path, never to navigate. */
const PARSE_BASE = 'https://console.invalid'

/**
 * Only a same-origin console path is allowed as a post-sign-in target: an
 * absolute path that resolves on this origin, never a scheme, another host
 * (`//host`), a backslash form or the sign-in pages themselves. The result is
 * rebuilt from the parsed path and query, so it can never name another origin.
 */
export function safeConsolePath(raw: string | null | undefined): string {
  const next = raw ?? ''
  if (!next.startsWith('/') || next.startsWith('//') || next.includes('\\')) return CONSOLE_ROOT
  let url: URL
  try {
    url = new URL(next, PARSE_BASE)
  } catch {
    return CONSOLE_ROOT
  }
  if (url.origin !== PARSE_BASE) return CONSOLE_ROOT
  if (url.pathname === '/login' || url.pathname.startsWith('/login/')) return CONSOLE_ROOT
  return url.pathname + url.search
}

/** The ?next= of the current page, sanitized. */
export function nextFromLocation(): string {
  if (typeof window === 'undefined') return CONSOLE_ROOT
  return safeConsolePath(new URLSearchParams(window.location.search).get('next'))
}

/** Keeps the post-sign-in target across the round trip to the IdP. */
export function rememberNext(next: string) {
  try {
    window.sessionStorage.setItem(NEXT_KEY, safeConsolePath(next))
  } catch {
    // Storage unavailable: the console opens on its overview.
  }
}

/** Returns (and forgets) the target remembered before going to the IdP. */
export function takeRememberedNext(): string {
  try {
    const v = window.sessionStorage.getItem(NEXT_KEY)
    window.sessionStorage.removeItem(NEXT_KEY)
    return safeConsolePath(v)
  } catch {
    return CONSOLE_ROOT
  }
}

/**
 * The authorization URL comes from the API, built from the configured IdP.
 * Refuse anything that is not http(s) so a bad value cannot run script.
 */
export function isNavigableURL(raw: string): boolean {
  try {
    const u = new URL(raw)
    return u.protocol === 'https:' || u.protocol === 'http:'
  } catch {
    return false
  }
}
