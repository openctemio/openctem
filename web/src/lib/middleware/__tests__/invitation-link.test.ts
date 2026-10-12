/**
 * @vitest-environment node
 */
import { describe, it, expect } from 'vitest'
import { NextRequest } from 'next/server'

import { handleLegacyInvitationLink, legacyInvitationTarget } from '../invitation-link'

const TOKEN = 'GWEu-eZWS_bitGWEu-eZWS_bitGWEu-eZWS_bit0123'

describe('legacy invitation links', () => {
  it('move the token from the path into the fragment', () => {
    expect(legacyInvitationTarget(`/invitations/${TOKEN}`)).toBe(`/invitations#token=${TOKEN}`)
    expect(legacyInvitationTarget(`/invitations/${TOKEN}/`)).toBe(`/invitations#token=${TOKEN}`)
  })

  it('leave every other path alone', () => {
    for (const p of [
      '/invitations',
      '/invitations/',
      '/invitations/a/b',
      '/invitationsx/abc',
      '/login',
      '/api/v1/invitations/abc',
    ]) {
      expect(legacyInvitationTarget(p), p).toBeNull()
    }
  })

  it('answer 307 to the same origin, with no referrer', () => {
    const res = handleLegacyInvitationLink(
      new NextRequest(`https://app.test/invitations/${TOKEN}?utm=x`)
    )
    expect(res?.status).toBe(307)
    expect(res?.headers.get('location')).toBe(`https://app.test/invitations#token=${TOKEN}`)
    expect(res?.headers.get('referrer-policy')).toBe('no-referrer')
  })

  it('do not answer other requests', () => {
    expect(handleLegacyInvitationLink(new NextRequest('https://app.test/invitations'))).toBeNull()
  })
})
