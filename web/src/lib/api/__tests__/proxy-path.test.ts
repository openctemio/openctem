import { describe, expect, it } from 'vitest'

import { proxyBackendPath } from '../proxy-path'

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

  it('refuses backslashes, which URL parsing treats as separators', () => {
    expect(proxyBackendPath(['x', '..\\..\\health'])).toBeNull()
  })
})
