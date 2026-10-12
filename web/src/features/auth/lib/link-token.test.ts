import { afterEach, describe, expect, it } from 'vitest'

import { readLinkToken } from './link-token'

// The emailed reset and setup links carry their token in the fragment; links
// sent earlier carried it in the query. Both work, and the token leaves the
// address bar at once.
describe('readLinkToken', () => {
  afterEach(() => window.history.replaceState(null, '', '/'))

  it('reads the fragment and removes it', () => {
    window.history.replaceState(null, '', '/reset-password#token=abc')
    expect(readLinkToken()).toBe('abc')
    expect(window.location.hash).toBe('')
  })

  it('still reads a query token from an older link and removes it', () => {
    window.history.replaceState(null, '', '/set-password?token=old')
    expect(readLinkToken()).toBe('old')
    expect(window.location.search).toBe('')
  })

  it('answers empty when the link has no token', () => {
    window.history.replaceState(null, '', '/reset-password')
    expect(readLinkToken()).toBe('')
  })
})
