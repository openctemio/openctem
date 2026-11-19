import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('next/navigation', () => ({ redirect: vi.fn() }))
const jar = new Map<string, string>()
vi.mock('next/headers', () => ({
  cookies: vi.fn(async () => ({
    get: vi.fn((name: string) => (jar.has(name) ? { value: jar.get(name) } : undefined)),
    set: vi.fn(),
    delete: vi.fn(),
  })),
  headers: vi.fn(async () => new Headers()),
}))
vi.mock('@/lib/cookies-server', () => ({
  setServerCookie: vi.fn(),
  removeServerCookie: vi.fn(async () => undefined),
}))

import { env } from '@/lib/env'
import { selectTenantAction } from './local-auth-actions'

// The invitation page tells a refusal "for now" (too many requests, a server
// failure, no answer) from a refusal about the membership, so the action
// hands the status and the server's Retry-After on.
describe('selectTenantAction refusals', () => {
  afterEach(() => {
    jar.clear()
    vi.unstubAllGlobals()
  })

  it('carries a 429 status and its Retry-After', async () => {
    jar.set(env.auth.refreshCookieName, 'refresh-abc')
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(JSON.stringify({ code: 'RATE_LIMIT_EXCEEDED', message: 'slow down' }), {
            status: 429,
            headers: { 'Retry-After': '17' },
          })
      )
    )
    const r = await selectTenantAction('t1')
    expect(r).toMatchObject({
      success: false,
      code: 'RATE_LIMIT_EXCEEDED',
      status: 429,
      retryAfter: '17',
    })
  })

  it('reports no answer from the API as status 0', async () => {
    jar.set(env.auth.refreshCookieName, 'refresh-abc')
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('fetch failed')
      })
    )
    const r = await selectTenantAction('t1')
    expect(r).toMatchObject({ success: false, status: 0 })
  })
})
