/**
 * The one rule for ending a session in the browser: only a dead session
 * (the refresh itself refused with 401, or a code that says the session is
 * gone) signs the person out. An organization that holds the session back,
 * a route that needs an organization, and a server or network failure never
 * do.
 */
import { describe, expect, it } from 'vitest'

import {
  readWelcomeNotice,
  refreshFailureAction,
  twoFactorSetupHref,
  welcomeNoticeHref,
} from '../refresh-failure'

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

  it.each([
    'ORGANIZATION_ACCESS_DENIED',
    'ORGANIZATION_SUSPENDED',
    'SSO_REQUIRED',
    'MFA_IDP_EVIDENCE_REQUIRED',
    'EMAIL_NOT_VERIFIED',
    'PERSONAL_ACCOUNTS_BLOCKED',
  ])('keeps the session and opens the account space: %s', (code) => {
    expect(refreshFailureAction(403, code)).toBe('account_space')
  })

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
    // The literal link of Account > Security (two-factor-card.tsx).
    expect(twoFactorSetupHref('/account/security')).toBe(
      '/two-factor-setup?next=%2Faccount%2Fsecurity'
    )
  })
})

describe('welcomeNoticeHref', () => {
  it.each([
    ['SSO_REQUIRED', 'sso_required'],
    ['MFA_IDP_EVIDENCE_REQUIRED', 'idp_mfa_required'],
    ['ORGANIZATION_SUSPENDED', 'organization_suspended'],
    ['EMAIL_NOT_VERIFIED', 'email_not_verified'],
    ['PERSONAL_ACCOUNTS_BLOCKED', 'personal_accounts_blocked'],
    ['OWN_SIGN_IN_REQUIRED', 'own_sign_in_required'],
  ])('names the reason of %s and the organization', (code, notice) => {
    expect(welcomeNoticeHref(code, 'acme')).toBe(`/welcome?notice=${notice}&org=acme`)
  })

  it('is the plain account space for another code, and drops a slug that is not one', () => {
    expect(welcomeNoticeHref('SOMETHING_NEW', 'acme')).toBe('/welcome')
    expect(welcomeNoticeHref(undefined)).toBe('/welcome')
    expect(welcomeNoticeHref('SSO_REQUIRED', '../evil?x=1')).toBe('/welcome?notice=sso_required')
  })
})

describe('readWelcomeNotice', () => {
  it('reads a known notice and a valid slug', () => {
    expect(readWelcomeNotice('sso_required', 'acme-2')).toEqual({
      notice: 'sso_required',
      org: 'acme-2',
    })
  })

  it('shows nothing for an unknown value (a crafted link puts no text on the page)', () => {
    expect(readWelcomeNotice('<script>', 'acme')).toBeUndefined()
    expect(readWelcomeNotice(null, 'acme')).toBeUndefined()
  })

  it('drops an organization that is not a slug', () => {
    expect(readWelcomeNotice('organization_suspended', 'Evil Corp<b>')).toEqual({
      notice: 'organization_suspended',
      org: undefined,
    })
  })
})
