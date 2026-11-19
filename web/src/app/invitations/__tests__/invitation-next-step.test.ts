import { describe, expect, it } from 'vitest'

import { invitationNextStep, invitationNextStepHref } from '../invitation-next-step'

describe('invitationNextStep', () => {
  it.each([
    ['SSO_REQUIRED', 'identity_provider'],
    ['MFA_IDP_EVIDENCE_REQUIRED', 'identity_provider_mfa'],
    ['OWN_SIGN_IN_REQUIRED', 'own_sign_in'],
    ['INVITATION_FOR_ANOTHER_ADDRESS', 'other_address'],
  ])('%s has its own next step', (code, step) => {
    expect(invitationNextStep(code)).toBe(step)
  })

  it.each([
    undefined,
    null,
    '',
    'MFA_ENROLLMENT_REQUIRED',
    'INVITATION_NO_LONGER_VALID',
    'FORBIDDEN',
  ])('leaves %j to the page (the 2FA step, or a plain error)', (code) => {
    expect(invitationNextStep(code)).toBeNull()
  })
})

describe('invitationNextStepHref', () => {
  const to = { slug: 'acme', email: 'person@example.com', invitationPath: '/invitations' }

  it('sends an identity provider step to that organization on the sign-in page', () => {
    expect(invitationNextStepHref('identity_provider', to)).toBe('/login?org=acme')
    expect(invitationNextStepHref('identity_provider_mfa', to)).toBe('/login?org=acme')
  })

  it('sends the account steps to sign-in for the invited address, back to the invitation', () => {
    for (const step of ['own_sign_in', 'other_address'] as const) {
      const url = new URL(invitationNextStepHref(step, to), 'http://localhost')
      expect(url.pathname).toBe('/login')
      expect(url.searchParams.get('returnTo')).toBe('/invitations')
      expect(url.searchParams.get('email')).toBe('person@example.com')
    }
  })

  it('never puts the invitation token in the URL', () => {
    expect(invitationNextStepHref('other_address', to)).not.toMatch(/token/)
  })
})
