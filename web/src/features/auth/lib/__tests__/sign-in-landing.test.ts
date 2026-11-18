/**
 * Where a social sign-in lands (sign-in-landing.ts, continue-href.ts): from
 * the memberships, never from a refusal, and never off-site.
 */
import { describe, expect, it, vi } from 'vitest'

vi.mock('next/headers', () => ({ cookies: vi.fn() }))

import { continueHref, landingHref } from '../continue-href'
import { landingFor, type MembershipRow } from '../sign-in-landing'

const ORG = '0b1e2c3d-0000-4000-8000-000000000001'

function row(over: Partial<MembershipRow> = {}): MembershipRow {
  return { id: ORG, slug: 'acme', name: 'Acme', role: 'member', ...over }
}

describe('landingFor', () => {
  it('no membership: the account space', () => {
    expect(landingFor([])).toEqual({ kind: 'account' })
  })
  it('only blocked memberships: the account space', () => {
    expect(landingFor([row({ blocked_reason: 'suspended' })])).toEqual({ kind: 'account' })
  })
  it('one organization it can open: that one', () => {
    expect(landingFor([row(), row({ id: 'x', blocked_reason: 'expired' })])).toEqual({
      kind: 'one',
      row: row(),
    })
  })
  it('several: the picker, with the open ones only', () => {
    const got = landingFor([row(), row({ id: 'b' }), row({ id: 'c', blocked_reason: 'suspended' })])
    expect(got.kind).toBe('choose')
    expect(got.kind === 'choose' && got.open.map((r) => r.id)).toEqual([ORG, 'b'])
  })
})

describe('landingHref', () => {
  it('a new account with no organization lands on /welcome, not on the dashboard', () => {
    expect(landingHref({ kind: 'account' }, '/')).toBe('/welcome')
    expect(landingHref({ kind: 'account' }, '/findings')).toBe('/welcome')
  })
  it('an invited person without an organization goes back to the invitation', () => {
    expect(landingHref({ kind: 'account' }, '/invitations')).toBe('/invitations')
    expect(landingHref({ kind: 'account' }, '/account/security/')).toBe('/account/security/')
    expect(landingHref({ kind: 'account' }, '/invitations/x')).toBe('/welcome')
  })
  it('refused by its one organization: the account space names the reason and the organization', () => {
    expect(
      landingHref({ kind: 'account', refusal: { code: 'SSO_REQUIRED', slug: 'acme' } }, '/')
    ).toBe('/welcome?notice=sso_required&org=acme')
    expect(
      landingHref(
        { kind: 'account', refusal: { code: 'OWN_SIGN_IN_REQUIRED', slug: 'acme' } },
        '/findings'
      )
    ).toBe('/welcome?notice=own_sign_in_required&org=acme')
    // An unknown code: the plain account space; the page asked for still wins
    // when an account session may open it.
    expect(landingHref({ kind: 'account', refusal: { code: 'NEW', slug: 'acme' } }, '/')).toBe(
      '/welcome'
    )
    expect(
      landingHref(
        { kind: 'account', refusal: { code: 'SSO_REQUIRED', slug: 'acme' } },
        '/account/security'
      )
    ).toBe('/account/security')
  })
  it('an organization that requires 2FA opens its setup, then the organization', () => {
    expect(landingHref({ kind: 'two_factor', tenantId: ORG }, '/findings')).toBe(
      `/two-factor-setup?next=%2Ffindings&org=${ORG}`
    )
  })
  it('an existing member lands where they were going', () => {
    expect(landingHref({ kind: 'organization', tenantId: ORG }, '/findings?x=1')).toBe(
      '/findings?x=1'
    )
  })
  it('several organizations: the picker', () => {
    expect(landingHref({ kind: 'choose' }, '/')).toBe('/select-tenant')
  })
  it('a session that could not start: /welcome says so instead of looping', () => {
    expect(landingHref({ kind: 'unavailable' }, '/')).toBe('/welcome?start_failed=1')
  })
  it('a dead session: sign in', () => {
    expect(landingHref({ kind: 'signed_out' }, '/findings')).toBe('/login')
  })
  it.each(['//evil.example', 'https://evil.example/', 'javascript:alert(1)', '/\\evil.example'])(
    'never redirects off-site: %j',
    (bad) => {
      expect(landingHref({ kind: 'organization', tenantId: ORG }, bad)).toBe('/')
      expect(continueHref(bad)).toBe('/auth/continue')
    }
  )
})
