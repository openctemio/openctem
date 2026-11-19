/**
 * @vitest-environment node
 *
 * The API's rotation grace gives a just-rotated refresh token's successor
 * only to the same client, judged by User-Agent. The console calls the API
 * from its server, so it must forward the browser's User-Agent; otherwise
 * every session looks like one client ("node") and the check means nothing.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { headers } from 'next/headers'

vi.mock('next/headers', () => ({ cookies: vi.fn(), headers: vi.fn() }))

import { callRefreshEndpoint } from '../server-refresh'

describe('callRefreshEndpoint client headers', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('forwards the browser User-Agent to /auth/refresh', async () => {
    vi.mocked(headers).mockResolvedValue(
      new Headers({ 'user-agent': 'Mozilla/5.0 BrowserA' }) as unknown as Awaited<
        ReturnType<typeof headers>
      >
    )
    const fetchMock = vi.fn(async () => new Response('{}', { status: 401 }))
    vi.stubGlobal('fetch', fetchMock)

    await callRefreshEndpoint('rt', 'tenant')

    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toMatch(/\/api\/v1\/auth\/refresh$/)
    expect((init.headers as Record<string, string>)['User-Agent']).toBe('Mozilla/5.0 BrowserA')
  })
})
