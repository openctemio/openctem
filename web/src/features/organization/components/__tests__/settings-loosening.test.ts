import { describe, expect, it } from 'vitest'
import { looseningsOf, signInFormFrom, type SignInForm } from '../authentication-settings'
import { lastChangeOf, changedFields } from '../last-changed'
import type { AuditLog } from '../../types/audit.types'

const base: SignInForm = {
  ...signInFormFrom(undefined),
  mfa_required: true,
  mfa_required_for_admins: true,
  ip_whitelist: '203.0.113.0/24',
  allowed_domains: 'example.com',
  email_verification_mode: 'always',
  personal_accounts: 'blocked',
  invitees: 'verified_domains',
  external_access_end_required: true,
  jit_requires_approval: true,
}

describe('looseningsOf (sign-in)', () => {
  it('reports nothing when nothing weakens', () => {
    expect(looseningsOf(base, base)).toEqual([])
    expect(looseningsOf(base, { ...base, ip_whitelist: '' + base.ip_whitelist + '\n' })).toEqual([])
  })

  it('reports every weakening change', () => {
    const next: SignInForm = {
      ...base,
      mfa_required: false,
      mfa_required_for_admins: false,
      ip_whitelist: '',
      allowed_domains: 'example.com\nother.test',
      email_verification_mode: 'never',
      personal_accounts: 'allowed',
      invitees: 'any',
      external_access_end_required: false,
      jit_requires_approval: false,
      sso_exceptions: [{ user_id: 'u1' } as SignInForm['sso_exceptions'][number]],
    }
    expect(looseningsOf(base, next).sort()).toEqual(
      [
        'mfaOff',
        'mfaAdminsOff',
        'ipEmptied',
        'domainsWidened',
        'emailNever',
        'personalLooser',
        'inviteesAny',
        'externalEndOff',
        'jitOff',
        'ssoExceptionAdded',
      ].sort()
    )
  })

  it('tightening is never reported', () => {
    const loose = signInFormFrom(undefined)
    expect(looseningsOf(loose, base)).toEqual([])
  })

  it('a wider allowlist is reported, a narrower one is not', () => {
    expect(looseningsOf(base, { ...base, ip_whitelist: '203.0.113.0/24\n198.51.100.7' })).toEqual([
      'ipWidened',
    ])
    expect(looseningsOf({ ...base, ip_whitelist: 'a\nb' }, { ...base, ip_whitelist: 'a' })).toEqual(
      []
    )
  })
})

describe('lastChangeOf', () => {
  const log = (id: string, before: Record<string, unknown>): AuditLog =>
    ({ id, changes: { before, after: before } }) as unknown as AuditLog

  it('picks the newest change that touched one of the fields', () => {
    const logs = [
      log('a', { website: 'x' }),
      log('b', { ip_whitelist: [] }),
      log('c', { mfa_required: true }),
    ]
    expect(lastChangeOf(logs, ['mfa_required', 'ip_whitelist'])?.id).toBe('b')
    expect(lastChangeOf(logs, ['nothing'])).toBeUndefined()
  })

  it('matches nested keys by prefix', () => {
    expect(changedFields(log('a', { 'sso_exceptions.0.user_id': 'u' }))).toEqual([
      'sso_exceptions.0.user_id',
    ])
    expect(
      lastChangeOf([log('a', { 'sso_exceptions.0.user_id': 'u' })], ['sso_exceptions'])?.id
    ).toBe('a')
  })
})
