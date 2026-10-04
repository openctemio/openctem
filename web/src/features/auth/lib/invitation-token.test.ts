import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  clearInvitationToken,
  invitationLink,
  readStashedInvitationToken,
  stashInvitationToken,
  takeInvitationToken,
} from './invitation-token'

const TOKEN = 'GWEu-eZWS_bitGWEu-eZWS_bitGWEu-eZWS_bit0123'

describe('invitation token', () => {
  beforeEach(() => {
    window.sessionStorage.clear()
    window.history.replaceState(null, '', '/invitations')
  })
  afterEach(() => vi.restoreAllMocks())

  it('builds the fragment link (the token never reaches a server)', () => {
    expect(invitationLink('https://x.test/', TOKEN)).toBe(
      `https://x.test/invitations#token=${TOKEN}`
    )
  })

  it('takes the token from the fragment, keeps it for the tab and removes it from the URL', () => {
    window.history.replaceState(null, '', `/invitations?x=1#token=${TOKEN}`)
    expect(takeInvitationToken()).toBe(TOKEN)
    expect(window.location.hash).toBe('')
    expect(window.location.href).not.toContain(TOKEN)
    expect(window.location.search).toBe('?x=1')
    expect(readStashedInvitationToken()).toBe(TOKEN)
    // Later visits in the same tab find it without a fragment.
    expect(takeInvitationToken()).toBe(TOKEN)
  })

  it('refuses a malformed token and still strips the fragment', () => {
    window.history.replaceState(null, '', '/invitations#token=%3Cscript%3E')
    expect(takeInvitationToken()).toBeUndefined()
    expect(window.location.hash).toBe('')
    expect(readStashedInvitationToken()).toBeUndefined()
  })

  it('ignores an unrelated fragment', () => {
    window.history.replaceState(null, '', '/invitations#details')
    expect(takeInvitationToken()).toBeUndefined()
    expect(window.location.hash).toBe('#details')
  })

  it('forgets the token', () => {
    stashInvitationToken(TOKEN)
    clearInvitationToken()
    expect(readStashedInvitationToken()).toBeUndefined()
  })

  it('works without storage (private mode)', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked')
    })
    window.history.replaceState(null, '', `/invitations#token=${TOKEN}`)
    expect(takeInvitationToken()).toBe(TOKEN)
    expect(readStashedInvitationToken()).toBeUndefined()
  })
})
