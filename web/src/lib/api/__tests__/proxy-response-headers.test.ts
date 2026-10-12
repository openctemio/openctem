import { describe, expect, it } from 'vitest'

import {
  copyProxiedHeaders,
  PROXIED_RESPONSE_HEADERS,
  PROXIED_STREAM_HEADERS,
} from '../proxy-response-headers'

describe('proxy response headers', () => {
  it('keeps the API security headers on every proxied answer', () => {
    for (const list of [PROXIED_RESPONSE_HEADERS, PROXIED_STREAM_HEADERS]) {
      expect(list).toContain('content-security-policy')
      expect(list).toContain('x-content-type-options')
      expect(list).toContain('content-disposition')
    }
  })

  it('copies only the listed headers that are present', () => {
    const from = new Headers({
      'content-type': 'text/html',
      'content-security-policy': "default-src 'none'",
      'content-disposition': 'attachment; filename="report.html"',
      'x-internal': 'secret',
    })
    const to = new Headers()
    copyProxiedHeaders(from, to, PROXIED_RESPONSE_HEADERS)
    expect(to.get('content-security-policy')).toBe("default-src 'none'")
    expect(to.get('content-disposition')).toBe('attachment; filename="report.html"')
    expect(to.get('x-internal')).toBeNull()
    expect(to.get('x-total-count')).toBeNull()
  })
})
