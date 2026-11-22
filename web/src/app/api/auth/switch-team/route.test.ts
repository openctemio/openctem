/**
 * @vitest-environment node
 *
 * Switching organization calls /auth/token from the console's server. The
 * API's rotation grace binds a repeat of a rotated token to the client's
 * User-Agent, so the browser's must be forwarded, not this server's.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cookies, headers } from 'next/headers'
import { NextRequest } from 'next/server'

vi.mock('next/headers', () => ({ cookies: vi.fn(), headers: vi.fn() }))

vi.mock('@/lib/server-auth-cookies', async (orig) => ({
  ...(await orig<typeof import('@/lib/server-auth-cookies')>()),
  csrfRejection: () => null,
}))

import { POST } from './route'

describe('POST /api/auth/switch-team', () => {
  beforeEach(() => vi.unstubAllGlobals())

  it('forwards the browser User-Agent to /auth/token', async () => {
    vi.mocked(headers).mockResolvedValue(
      new Headers({ 'user-agent': 'Mozilla/5.0 BrowserB' }) as unknown as Awaited<
        ReturnType<typeof headers>
      >
    )
    vi.mocked(cookies).mockResolvedValue({
      get: (name: string) => (name.includes('refresh') ? { name, value: 'rt' } : undefined),
      set: vi.fn(),
      delete: vi.fn(),
    } as unknown as Awaited<ReturnType<typeof cookies>>)
    const fetchMock = vi.fn(async () => new Response('{"code":"X"}', { status: 403 }))
    vi.stubGlobal('fetch', fetchMock)

    await POST(
      new NextRequest('https://app.example.test/api/auth/switch-team', {
        method: 'POST',
        body: JSON.stringify({ tenant_id: 't1' }),
      })
    )

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toMatch(/\/api\/v1\/auth\/token$/)
    expect((init.headers as Record<string, string>)['User-Agent']).toBe('Mozilla/5.0 BrowserB')
  })
})
