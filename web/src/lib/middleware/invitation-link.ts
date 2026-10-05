/**
 * Invitation links sent before RFC-041 (api/docs/rfcs/RFC-041-api-path-design.md)
 * carry the token in the path: /invitations/{token}. The proxy answers them
 * with a 307 to /invitations#token={token} before any rendering, so the token
 * moves into the fragment (never sent to a server again) and the old URL is
 * replaced in the history. The invitation page then takes the token from the
 * fragment and removes it (features/auth/lib/invitation-token.ts).
 */

import { NextResponse, type NextRequest } from 'next/server'

const LEGACY_INVITATION_PATH = /^\/invitations\/([^/]+)\/?$/

/** The fragment URL for a legacy invitation path, or null for any other path. */
export function legacyInvitationTarget(pathname: string): string | null {
  const m = LEGACY_INVITATION_PATH.exec(pathname)
  if (!m) return null
  let token: string
  try {
    token = decodeURIComponent(m[1])
  } catch {
    return null
  }
  return `/invitations#token=${encodeURIComponent(token)}`
}

/** A 307 to the fragment form for a legacy invitation link, else null. */
export function handleLegacyInvitationLink(req: NextRequest): NextResponse | null {
  const target = legacyInvitationTarget(req.nextUrl.pathname)
  if (!target) return null
  const res = NextResponse.redirect(new URL(target, req.url), 307)
  // The old URL held the token: never let it travel on as a Referer.
  res.headers.set('Referrer-Policy', 'no-referrer')
  return res
}
