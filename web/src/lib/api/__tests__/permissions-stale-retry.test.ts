import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest'

// Fresh module per test: the client keeps refresh state between calls.
let post: typeof import('@/lib/api/client').post

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

const stale = () =>
  json(409, {
    code: 'permissions_stale',
    message: 'Your session is using outdated permissions. Refresh your token and retry.',
  })

const refreshed = () => json(200, { success: true, data: { access_token: 'fresh' } })

function stubFetch(responses: Record<string, Array<() => Response>>) {
  const calls: string[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      calls.push(url)
      const key = Object.keys(responses).find((k) => url.includes(k))
      const next = key ? responses[key].shift() : undefined
      if (!next) throw new Error(`unexpected request ${url}`)
      return next()
    })
  )
  return calls
}

// A role or team change bumps the user's permission version; the server then
// refuses writes from the older token with 409 permissions_stale before
// running them. The client gets a fresh token and retries once.
describe('apiClient on 409 permissions_stale', () => {
  beforeEach(async () => {
    vi.resetModules()
    window.localStorage.clear()
    ;({ post } = await import('@/lib/api/client'))
  })
  afterEach(() => vi.unstubAllGlobals())

  it('refreshes the token and retries the write once', async () => {
    const calls = stubFetch({
      '/api/v1/groups': [stale, () => json(201, { id: 'g1' })],
      '/api/auth/refresh': [refreshed],
    })
    await expect(post('/api/v1/groups', { name: 'SecOps' })).resolves.toEqual({ id: 'g1' })
    expect(calls.filter((u) => u.includes('/api/v1/groups'))).toHaveLength(2)
    expect(calls.filter((u) => u.includes('/api/auth/refresh'))).toHaveLength(1)
  })

  it('does not loop when the retry is refused again', async () => {
    const calls = stubFetch({
      '/api/v1/groups': [stale, stale],
      '/api/auth/refresh': [refreshed],
    })
    await expect(post('/api/v1/groups', { name: 'SecOps' })).rejects.toMatchObject({
      code: 'permissions_stale',
    })
    expect(calls.filter((u) => u.includes('/api/v1/groups'))).toHaveLength(2)
  })

  it('does not retry when the refresh fails', async () => {
    const calls = stubFetch({
      '/api/v1/groups': [stale],
      '/api/auth/refresh': [() => json(401, { success: false, error: { message: 'expired' } })],
    })
    await expect(post('/api/v1/groups', { name: 'SecOps' })).rejects.toMatchObject({
      code: 'permissions_stale',
    })
    expect(calls.filter((u) => u.includes('/api/v1/groups'))).toHaveLength(1)
  })
})
