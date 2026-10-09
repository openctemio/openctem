import { describe, expect, it } from 'vitest'

import { proxyCacheHeaders } from './proxy-cache-headers'

describe('proxyCacheHeaders', () => {
  it("forwards the API's no-store on secrets", () => {
    expect(proxyCacheHeaders('no-store', true)).toEqual({ 'Cache-Control': 'no-store' })
  })

  it('forwards public config caching (auth providers)', () => {
    expect(proxyCacheHeaders('public, max-age=60', false)).toEqual({
      'Cache-Control': 'public, max-age=60',
    })
  })

  it('keys a cacheable authenticated response by the session cookie', () => {
    // /me/bootstrap is private, max-age=300 and has the same URL for every
    // organization: without Vary: Cookie, switching organization could show
    // the previous one's copy.
    expect(proxyCacheHeaders('private, max-age=300', true)).toEqual({
      'Cache-Control': 'private, max-age=300',
      Vary: 'Cookie',
    })
  })

  it('stores nothing for unlabelled authenticated responses', () => {
    expect(proxyCacheHeaders(null, true)).toEqual({ 'Cache-Control': 'no-store' })
    expect(proxyCacheHeaders('  ', true)).toEqual({ 'Cache-Control': 'no-store' })
  })

  it('adds nothing to an unlabelled anonymous response', () => {
    expect(proxyCacheHeaders(null, false)).toEqual({})
  })

  it('passes the ETag of a response the browser may keep, so it can revalidate (304)', () => {
    // The asset type registry: private, no-cache + ETag (research/81).
    expect(proxyCacheHeaders('private, no-cache', true, '"abc"')).toEqual({
      'Cache-Control': 'private, no-cache',
      Vary: 'Cookie',
      ETag: '"abc"',
    })
  })

  it('never passes an ETag with no-store, or without the API caching decision', () => {
    expect(proxyCacheHeaders('no-store', true, '"abc"')).toEqual({ 'Cache-Control': 'no-store' })
    expect(proxyCacheHeaders(null, true, '"abc"')).toEqual({ 'Cache-Control': 'no-store' })
  })
})
