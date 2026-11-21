/**
 * The one next step after the API refused to accept an invitation, or to open
 * the organization it joined, for a reason this session cannot fix in place.
 * The invitation page then shows that step instead of offering Accept or Open
 * again (a second try gets the same refusal).
 *
 * Design: server/docs/development/auth-scenarios.md (no dead end).
 */

export type InvitationNextStep =
  /** The organization opens only for a sign-in through its own identity provider. */
  | 'identity_provider'
  /** As above, and that provider must also confirm a second factor. */
  | 'identity_provider_mfa'
  /** The session came from another organization's provider: the account's own sign-in. */
  | 'own_sign_in'
  /** The session's account is not the one the invitation was sent to. */
  | 'other_address'

/** Maps the API's refusal code to the next step; null when the page handles it otherwise. */
export function invitationNextStep(code: string | undefined | null): InvitationNextStep | null {
  switch (code) {
    case 'SSO_REQUIRED':
      return 'identity_provider'
    case 'MFA_IDP_EVIDENCE_REQUIRED':
      return 'identity_provider_mfa'
    case 'OWN_SIGN_IN_REQUIRED':
      return 'own_sign_in'
    case 'INVITATION_FOR_ANOTHER_ADDRESS':
      return 'other_address'
    default:
      return null
  }
}

/**
 * Where the step's button goes once this session is signed out: the
 * organization's identity provider on the sign-in page (?org=), or the
 * sign-in page for the invited address, coming back to the invitation (its
 * token stays in this tab).
 */
export function invitationNextStepHref(
  step: InvitationNextStep,
  to: { slug: string; email: string; invitationPath: string }
): string {
  const params = new URLSearchParams()
  if (step === 'identity_provider' || step === 'identity_provider_mfa') {
    params.set('org', to.slug)
  } else {
    params.set('returnTo', to.invitationPath)
    if (to.email) params.set('email', to.email)
  }
  return `/login?${params.toString()}`
}
