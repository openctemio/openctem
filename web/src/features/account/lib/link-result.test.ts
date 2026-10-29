import { describe, expect, it } from 'vitest'

import { linkResultHref, readLinkResult } from './link-result'

describe('link result', () => {
  it('round-trips a link and a refusal', () => {
    expect(linkResultHref('google')).toBe('/account/security?linked=google')
    expect(readLinkResult(new URLSearchParams('linked=google'))).toEqual({
      kind: 'linked',
      provider: 'google',
    })
    const href = linkResultHref('github', 'IDENTITY_LINKED_ELSEWHERE')
    expect(readLinkResult(new URL(href, 'https://x.example').searchParams)).toEqual({
      kind: 'error',
      provider: 'github',
      code: 'IDENTITY_LINKED_ELSEWHERE',
    })
  })

  it('ignores unknown providers and free text', () => {
    expect(readLinkResult(new URLSearchParams('linked=evil'))).toBeNull()
    expect(readLinkResult(new URLSearchParams('link_error=Call%20me'))).toBeNull()
    expect(readLinkResult(new URLSearchParams(''))).toBeNull()
  })
})
