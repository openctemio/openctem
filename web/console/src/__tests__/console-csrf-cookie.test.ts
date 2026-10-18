/**
 * @vitest-environment node
 *
 * The console's page cookie is `console_csrf`: the tenant site's `csrf_token`
 * (same host, other port) is never set or read by the console.
 */
import { describe, expect, it, vi } from 'vitest'
import { NextRequest } from 'next/server'

vi.mock('@/lib/env', () => ({
  env: { api: { url: 'http://api.test' }, auth: { refreshCookieName: 'r', cookieName: 'a' } },
}))

import { proxy } from '@console/proxy'

describe('console proxy page cookie', () => {
  it('sets console_csrf and never csrf_token', () => {
    const res = proxy(new NextRequest('https://c.example.test:8443/login'))
    expect(res.cookies.get('console_csrf')?.value).toMatch(/^[0-9a-f]{64}$/)
    expect(res.cookies.get('csrf_token')).toBeUndefined()
  })

  it('keeps an existing console_csrf, and sets its own beside a tenant csrf_token', () => {
    const kept = proxy(
      new NextRequest('https://c.example.test:8443/login', {
        headers: { cookie: 'console_csrf=mine' },
      })
    )
    expect(kept.cookies.get('console_csrf')).toBeUndefined()
    const beside = proxy(
      new NextRequest('https://c.example.test:8443/login', {
        headers: { cookie: 'csrf_token=tenant' },
      })
    )
    expect(beside.cookies.get('console_csrf')).toBeDefined()
  })
})
