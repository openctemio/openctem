import { describe, expect, it } from 'vitest'

import { isConsoleApiPath, proxyBackendPath } from '../proxy-path'

describe('proxyBackendPath', () => {
  it('joins ordinary segments', () => {
    expect(proxyBackendPath(['findings', 'abc-123', 'comments'])).toBe('findings/abc-123/comments')
  })

  it('keeps dots that are not whole segments', () => {
    expect(proxyBackendPath(['components', 'lodash@4.17.21'])).toBe('components/lodash@4.17.21')
    expect(proxyBackendPath(['files', '..hidden', 'a..b'])).toBe('files/..hidden/a..b')
  })

  it('refuses a decoded %2F traversal out of /api/v1', () => {
    // GET /api/v1/x/..%2F..%2F..%2Fhealth reached the API's /health.
    expect(proxyBackendPath(['x', '../../../health'])).toBeNull()
  })

  it('refuses bare dot segments', () => {
    expect(proxyBackendPath(['x', '..'])).toBeNull()
    expect(proxyBackendPath(['.', 'findings'])).toBeNull()
  })

  it('re-encodes a decoded ? # or % so it cannot become a query, fragment or second escape', () => {
    // GET /api/v1/findings/abc%3Fscope=all arrived as `abc?scope=all`.
    expect(proxyBackendPath(['findings', 'abc?scope=all'])).toBe('findings/abc%3Fscope=all')
    expect(proxyBackendPath(['findings', 'abc#frag'])).toBe('findings/abc%23frag')
    expect(proxyBackendPath(['files', '100%2F'])).toBe('files/100%252F')
    const url = new URL(`http://api.test/api/v1/${proxyBackendPath(['findings', 'a?b#c'])}`)
    expect(url.search).toBe('')
    expect(url.hash).toBe('')
    expect(url.pathname).toBe('/api/v1/findings/a%3Fb%23c')
  })

  it('leaves every other character as it was', () => {
    expect(proxyBackendPath(['components', 'pkg:npm', 'a b+c=d&e'])).toBe(
      'components/pkg:npm/a b+c=d&e'
    )
  })

  it('refuses backslashes, which URL parsing treats as separators', () => {
    expect(proxyBackendPath(['x', '..\\..\\health'])).toBeNull()
  })
})

describe('isConsoleApiPath', () => {
  it.each([
    [['admin', 'tenants']],
    [['admin']],
    [['Admin', 'auth', 'login']],
    [['', 'admin', 'tenants']],
    [['.', 'admin']],
    [['admin/tenants']],
    [['admin\\tenants']],
  ])('%j is the console API, never forwarded by the tenant proxy', (segments) => {
    expect(isConsoleApiPath(segments)).toBe(true)
  })

  it.each([[['findings']], [['administrators']], [['assets', 'admin']], [[]]])(
    '%j is not the console API',
    (segments) => {
      expect(isConsoleApiPath(segments)).toBe(false)
    }
  )
})
