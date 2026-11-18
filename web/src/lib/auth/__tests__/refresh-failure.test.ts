/**
 * The one rule for ending a session in the browser: only a dead session
 * (the refresh itself refused with 401, or a code that says the session is
 * gone) signs the person out. An organization that holds the session back,
 * a route that needs an organization, and a server or network failure never
 * do.
 */
import { describe, expect, it } from 'vitest'

import { refreshFailureAction, twoFactorSetupHref } from '../refresh-failure'

describe('refreshFailureAction', () => {
  it.each([
    [401, undefined],
    [401, 'SESSION_EXPIRED'],
    [401, 'REFRESH_TOKEN_REUSED'],
    [401, 'ACCOUNT_SESSION'],
    [401, 'NO_REFRESH_TOKEN'],
    [403, 'OWN_SIGN_IN_REQUIRED'],
  ])('signs out for a dead session: %i %s', (status, code) => {
    expect(refreshFailureAction(status, code)).toBe('sign_out')
  })

  it.each(['MFA_ENROLLMENT_REQUIRED'])(
    'keeps the session and opens the two-factor setup: %s',
    (code) => {
      expect(refreshFailureAction(403, code)).toBe('two_factor_setup')
    }
  )

  it.each(['ORGANIZATION_SUSPENDED', 'SSO_REQUIRED', 'MFA_IDP_EVIDENCE_REQUIRED'])(
    'keeps the session and opens the account space: %s',
    (code) => {
      expect(refreshFailureAction(403, code)).toBe('account_space')
    }
  )

  it.each([
    [0, undefined],
    [500, undefined],
    [502, 'ACCOUNT_ERROR'],
    [429, 'RATE_LIMITED'],
    [403, 'SOMETHING_NEW'],
  ])('keeps the session on a server or network failure: %i %s', (status, code) => {
    expect(refreshFailureAction(status, code)).toBe('keep')
  })

  it('never treats TENANT_REQUIRED as a dead session (it is not a refresh answer)', () => {
    expect(refreshFailureAction(403, 'TENANT_REQUIRED')).toBe('keep')
  })
})

describe('twoFactorSetupHref', () => {
  it('carries the page to come back to and the organization to open', () => {
    expect(twoFactorSetupHref('/findings?x=1', '0b1e2c3d-0000-4000-8000-000000000001')).toBe(
      '/two-factor-setup?next=%2Ffindings%3Fx%3D1&org=0b1e2c3d-0000-4000-8000-000000000001'
    )
    expect(twoFactorSetupHref('/')).toBe('/two-factor-setup?next=%2F')
  })
})
