import { describe, expect, it } from 'vitest'

import {
  blockedReasonText,
  canonicalMailbox,
  daysUntil,
  memberBadges,
  suspendedReasonText,
} from '../external-access'

const NOW = new Date('2026-10-08T12:00:00Z')
const keys = (m: Parameters<typeof memberBadges>[0], opts = {}) =>
  memberBadges(m, { now: NOW, ...opts }).map((b) => b.key)

describe('memberBadges', () => {
  it('shows nothing for an ordinary internal member', () => {
    expect(keys({ kind: 'internal', status: 'active' })).toEqual([])
  })

  it('names the source of an external member', () => {
    expect(keys({ kind: 'external', status: 'active', home_organization: 'Acme' })).toEqual([
      'external',
    ])
    expect(keys({ kind: 'external', status: 'active' })).toEqual(['unmanaged'])
    expect(keys({ kind: 'external', status: 'active', personal: true })).toEqual(['personal'])
  })

  it('adds the lapsed domain, the SSO exception and the end of access', () => {
    const b = memberBadges(
      {
        kind: 'external',
        status: 'active',
        personal: true,
        domain_lapsed: true,
        access_expires_at: '2026-10-13T12:00:00Z',
      },
      { now: NOW, ssoExceptionUntil: '2026-10-20T00:00:00Z' }
    )
    expect(b.map((x) => x.key)).toEqual(['personal', 'lapsed', 'exception', 'ends'])
    expect(b.find((x) => x.key === 'ends')).toMatchObject({ label: 'Ends in 5d', tone: 'warning' })
  })

  it('drops an expired SSO exception and a past end of access', () => {
    expect(
      keys(
        { kind: 'external', status: 'suspended', access_expires_at: '2026-10-01T00:00:00Z' },
        { ssoExceptionUntil: '2026-10-01T00:00:00Z' }
      )
    ).toEqual(['unmanaged'])
  })
})

describe('wording', () => {
  it('explains why an organization is blocked', () => {
    expect(blockedReasonText(undefined)).toBe('')
    expect(blockedReasonText('expired')).toBe('Your access ended')
    expect(blockedReasonText('personal_accounts_blocked')).toMatch(/personal email/)
    expect(blockedReasonText('something_new')).toBe('Your access is disabled')
  })

  it('explains why a member is disabled', () => {
    expect(suspendedReasonText('trust_revoked')).toBe('Trust ended')
    expect(suspendedReasonText(undefined)).toBe('')
  })
})

describe('canonicalMailbox', () => {
  it('folds Gmail dots and +tags, and only +tags elsewhere', () => {
    expect(canonicalMailbox('J.Doe+work@GoogleMail.com')).toBe('jdoe@gmail.com')
    expect(canonicalMailbox('a.b+x@corp.example')).toBe('a.b@corp.example')
    expect(canonicalMailbox('nope')).toBe('')
  })
})

describe('daysUntil', () => {
  it('counts whole days ahead', () => {
    expect(daysUntil('2026-10-09T12:00:00Z', NOW)).toBe(1)
    expect(daysUntil('2026-10-07T12:00:00Z', NOW)).toBe(-1)
  })
})
