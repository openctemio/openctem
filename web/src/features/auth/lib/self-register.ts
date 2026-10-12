/**
 * Self-registration rules.
 *
 * Accounts are created by administrators; people cannot sign themselves up.
 * The one exception is an invitation: someone who arrives from the invitation
 * page (/invitations) may create their own account for the invited email (the
 * API accepts POST /auth/register with that `invitation_token` even when
 * registration is disabled). A deployment can still turn open registration on,
 * which the API reports as `registration_enabled` on GET /auth/providers.
 *
 * The token itself never rides in returnTo (a query string reaches server
 * logs): the invitation page keeps it for the tab, see ./invitation-token.ts.
 * Old links carry it in the path (/invitations/{token}); those still work.
 */

import { readStashedInvitationToken } from './invitation-token'

const INVITATION_RETURN_TO = /^\/invitations(?:[/?#]|$)/
const LEGACY_INVITATION_PATH = /^\/invitations\/([^/?#]+)/

/** True when returnTo points at the invitation page. Pure, so SSR-safe. */
export function isInvitationReturnTo(returnTo: string | null | undefined): boolean {
  return !!returnTo && INVITATION_RETURN_TO.test(returnTo)
}

/**
 * The invitation token for a returnTo that points at the invitation page: the
 * one in a legacy "/invitations/{token}" path, else the one this tab keeps.
 */
export function invitationTokenFromReturnTo(
  returnTo: string | null | undefined
): string | undefined {
  if (!returnTo || !isInvitationReturnTo(returnTo)) return undefined
  return returnTo.match(LEGACY_INVITATION_PATH)?.[1] ?? readStashedInvitationToken()
}

/** True when the visitor may see "Create an account" affordances. */
export function canSelfRegister(
  registrationEnabled: boolean | undefined,
  returnTo: string | null | undefined
): boolean {
  return registrationEnabled === true || isInvitationReturnTo(returnTo)
}

/**
 * The /register link, carrying the invitation `returnTo` (so the register form
 * sends the invitation token) and the email to pre-fill.
 */
export function registerHref({
  returnTo,
  email,
}: { returnTo?: string | null; email?: string | null } = {}): string {
  const params = new URLSearchParams()
  if (returnTo && isInvitationReturnTo(returnTo)) params.set('returnTo', returnTo)
  if (email) params.set('email', email)
  const qs = params.toString()
  return qs ? `/register?${qs}` : '/register'
}
