import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

import {
  navigateAfterSessionChange,
  sessionLandingPath,
  stashSessionFlash,
  takeSessionFlash,
} from '../session-navigation'
import {
  readStashedInvitationToken,
  stashInvitationToken,
} from '@/features/auth/lib/invitation-token'

const TOKEN = 'GWEu-eZWS_bitGWEu-eZWS_bitGWEu-eZWS_bit0123'

describe('sessionLandingPath', () => {
  it.each([
    ['/', '/'],
    ['/findings?severity=high', '/findings?severity=high'],
    ['/invitations', '/invitations'],
    ['/login?mfa=setup', '/login?mfa=setup'],
  ])('keeps the same-origin path %s', (input, expected) => {
    expect(sessionLandingPath(input)).toBe(expected)
  })

  it.each([
    'https://evil.example.com/',
    '//evil.example.com',
    '/\\evil.example.com',
    '/\t/evil.example.com',
    'javascript:alert(1)',
    '/javascript:alert(1)',
    'findings',
    '',
    null,
    undefined,
  ])('never leaves the site for %j', (input) => {
    expect(sessionLandingPath(input as string | null | undefined)).toBe('/')
  })
})

describe('session flash', () => {
  beforeEach(() => window.sessionStorage.clear())

  it('is shown once', () => {
    stashSessionFlash({ kind: 'success', title: 'You joined Acme.', description: 'More' })
    expect(takeSessionFlash()).toEqual({
      kind: 'success',
      title: 'You joined Acme.',
      description: 'More',
    })
    expect(takeSessionFlash()).toBeNull()
  })

  it('ignores a malformed or foreign value', () => {
    window.sessionStorage.setItem('openctem.session-flash', '{not json')
    expect(takeSessionFlash()).toBeNull()
    window.sessionStorage.setItem(
      'openctem.session-flash',
      JSON.stringify({ kind: 'error', title: 'x' })
    )
    expect(takeSessionFlash()).toBeNull()
    window.sessionStorage.setItem('openctem.session-flash', JSON.stringify({ kind: 'info' }))
    expect(takeSessionFlash()).toBeNull()
  })

  it('bounds the kept text', () => {
    stashSessionFlash({ kind: 'info', title: 'x'.repeat(5000) })
    expect(takeSessionFlash()?.title).toHaveLength(300)
  })
})

describe('navigateAfterSessionChange', () => {
  const original = window.location
  const assign = vi.fn()
  const replace = vi.fn()

  beforeEach(() => {
    window.sessionStorage.clear()
    assign.mockReset()
    replace.mockReset()
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { ...original, assign, replace },
    })
  })
  afterEach(() => {
    Object.defineProperty(window, 'location', { configurable: true, value: original })
  })

  it('loads the page as a new document (not a client-side push)', () => {
    navigateAfterSessionChange('/')
    expect(assign).toHaveBeenCalledWith('/')
    expect(replace).not.toHaveBeenCalled()
  })

  it('replaces the history entry when asked', () => {
    navigateAfterSessionChange('/welcome', { replace: true })
    expect(replace).toHaveBeenCalledWith('/welcome')
    expect(assign).not.toHaveBeenCalled()
  })

  it('refuses an open redirect', () => {
    navigateAfterSessionChange('https://evil.example.com/steal')
    navigateAfterSessionChange('//evil.example.com')
    expect(assign.mock.calls).toEqual([['/'], ['/']])
  })

  it('forgets the invitation token, except on the way back to the invitation', () => {
    stashInvitationToken(TOKEN)
    navigateAfterSessionChange('/invitations')
    expect(readStashedInvitationToken()).toBe(TOKEN)

    navigateAfterSessionChange('/')
    expect(readStashedInvitationToken()).toBeUndefined()
  })

  it('keeps the message for the page that loads', () => {
    navigateAfterSessionChange('/', { flash: { kind: 'success', title: 'You joined Acme.' } })
    expect(takeSessionFlash()).toEqual({ kind: 'success', title: 'You joined Acme.' })
  })
})
