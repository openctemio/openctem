import { beforeEach, describe, it, expect } from 'vitest'

import { stashInvitationToken } from './invitation-token'
import {
  canSelfRegister,
  invitationTokenFromReturnTo,
  isInvitationReturnTo,
  registerHref,
} from './self-register'

const TOKEN = 'GWEu-eZWS_bitGWEu-eZWS_bitGWEu-eZWS_bit0123'

describe('isInvitationReturnTo', () => {
  it('matches the invitation page, with or without a legacy token', () => {
    expect(isInvitationReturnTo('/invitations')).toBe(true)
    expect(isInvitationReturnTo('/invitations?x=1')).toBe(true)
    expect(isInvitationReturnTo('/invitations/abc123')).toBe(true)
  })

  it('matches nothing else', () => {
    expect(isInvitationReturnTo(undefined)).toBe(false)
    expect(isInvitationReturnTo('')).toBe(false)
    expect(isInvitationReturnTo('/invitationsx')).toBe(false)
    expect(isInvitationReturnTo('/dashboard')).toBe(false)
    expect(isInvitationReturnTo('https://evil.test/invitations')).toBe(false)
  })
})

describe('invitationTokenFromReturnTo', () => {
  beforeEach(() => window.sessionStorage.clear())

  it('reads the token this tab keeps for /invitations', () => {
    expect(invitationTokenFromReturnTo('/invitations')).toBeUndefined()
    stashInvitationToken(TOKEN)
    expect(invitationTokenFromReturnTo('/invitations')).toBe(TOKEN)
  })

  it('still understands a legacy /invitations/{token} returnTo', () => {
    expect(invitationTokenFromReturnTo('/invitations/abc123')).toBe('abc123')
    expect(invitationTokenFromReturnTo('/invitations/abc123/accept')).toBe('abc123')
    expect(invitationTokenFromReturnTo('/invitations/abc123?x=1')).toBe('abc123')
  })

  it('returns undefined for anything else', () => {
    stashInvitationToken(TOKEN)
    expect(invitationTokenFromReturnTo(undefined)).toBeUndefined()
    expect(invitationTokenFromReturnTo(null)).toBeUndefined()
    expect(invitationTokenFromReturnTo('')).toBeUndefined()
    expect(invitationTokenFromReturnTo('/dashboard')).toBeUndefined()
    expect(invitationTokenFromReturnTo('https://evil.test/invitations/x')).toBeUndefined()
  })
})

describe('canSelfRegister', () => {
  it('is false by default (registration disabled, flag missing, or still loading)', () => {
    expect(canSelfRegister(false, null)).toBe(false)
    expect(canSelfRegister(undefined, null)).toBe(false)
    expect(canSelfRegister(undefined, '/dashboard')).toBe(false)
  })

  it('is true when the server enables open registration', () => {
    expect(canSelfRegister(true, null)).toBe(true)
  })

  it('is true for an invited visitor even when registration is disabled', () => {
    expect(canSelfRegister(false, '/invitations')).toBe(true)
    expect(canSelfRegister(undefined, '/invitations/tok')).toBe(true)
  })
})

describe('registerHref', () => {
  it('is plain /register with nothing to carry', () => {
    expect(registerHref()).toBe('/register')
    expect(registerHref({ returnTo: '/dashboard' })).toBe('/register')
  })

  it('carries the invitation returnTo and the email', () => {
    const href = registerHref({ returnTo: '/invitations', email: 'a+b@co.com' })
    const url = new URL(href, 'http://x')
    expect(url.pathname).toBe('/register')
    expect(url.searchParams.get('returnTo')).toBe('/invitations')
    expect(url.searchParams.get('email')).toBe('a+b@co.com')
  })
})
