import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'

// Fresh module per test: the client keeps refresh state between calls.
let get: typeof import('@/lib/api/client').get

const staleOk = () =>
  new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'content-type': 'application/json', 'x-permission-stale': 'true' },
  })

const refreshed = () =>
  new Response(JSON.stringify({ success: true, data: { access_token: 'fresh' } }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })

function stubFetch() {
  const calls: string[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      calls.push(url)
      return url.includes('/api/auth/refresh') ? refreshed() : staleOk()
    })
  )
  return calls
}

const refreshes = (calls: string[]) => calls.filter((u) => u.includes('/api/auth/refresh')).length

// A role or team change bumps the user's permission version; any answer then
// carries X-Permission-Stale. The client renews its token right away, so the
// user's next write goes through instead of being refused with 409.
describe('apiClient on X-Permission-Stale', () => {
  beforeEach(async () => {
    vi.resetModules()
    window.localStorage.clear()
    ;({ get } = await import('@/lib/api/client'))
  })
  afterEach(() => vi.unstubAllGlobals())

  it('renews the token after a read answered with the stale header', async () => {
    const calls = stubFetch()
    await get('/api/v1/assets')
    await vi.waitFor(() => expect(refreshes(calls)).toBe(1))
  })

  it('renews at most once for a burst of stale answers', async () => {
    const calls = stubFetch()
    await Promise.all([get('/api/v1/assets'), get('/api/v1/findings'), get('/api/v1/scans')])
    await get('/api/v1/teams')
    await vi.waitFor(() => expect(refreshes(calls)).toBe(1))
  })
})
