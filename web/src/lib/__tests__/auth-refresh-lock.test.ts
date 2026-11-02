import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  AUTH_REFRESH_AT_KEY,
  AUTH_REFRESH_LOCK,
  refreshSessionShared,
  resetBrowserRefreshState,
  withAuthRefreshLock,
} from '../auth-refresh-lock'

// A Web Locks stand-in: one holder at a time per name, FIFO.
function fakeLocks() {
  const queues = new Map<string, Promise<unknown>>()
  const names: string[] = []
  return {
    names,
    request<T>(name: string, cb: () => Promise<T>): Promise<T> {
      names.push(name)
      const prev = queues.get(name) ?? Promise.resolve()
      const run = prev.then(cb, cb)
      queues.set(
        name,
        run.catch(() => undefined)
      )
      return run
    },
  }
}

describe('withAuthRefreshLock (RFC-045)', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('serializes refreshes from several callers (as from several tabs)', async () => {
    const locks = fakeLocks()
    vi.stubGlobal('navigator', { locks })
    const order: string[] = []
    let release!: () => void
    const first = withAuthRefreshLock(async () => {
      order.push('first:start')
      await new Promise<void>((r) => (release = r))
      order.push('first:end')
      return 1
    })
    const second = withAuthRefreshLock(async () => {
      order.push('second:start')
      return 2
    })
    await Promise.resolve()
    await Promise.resolve()
    expect(order).toEqual(['first:start'])
    release()
    expect(await first).toBe(1)
    expect(await second).toBe(2)
    expect(order).toEqual(['first:start', 'first:end', 'second:start'])
    expect(locks.names).toEqual([AUTH_REFRESH_LOCK, AUTH_REFRESH_LOCK])
  })

  it('runs the refresh directly where Web Locks are unavailable', async () => {
    vi.stubGlobal('navigator', {})
    await expect(withAuthRefreshLock(async () => 'ok')).resolves.toBe('ok')
  })
})

describe('refreshSessionShared', () => {
  afterEach(() => {
    resetBrowserRefreshState()
    vi.unstubAllGlobals()
    try {
      window.localStorage.removeItem(AUTH_REFRESH_AT_KEY)
    } catch {
      // ignore
    }
  })

  const okResponse = () =>
    new Response(JSON.stringify({ success: true, data: { access_token: 'new-access' } }), {
      status: 200,
    })

  it('parallel callers in a tab make one network refresh', async () => {
    vi.stubGlobal('navigator', { locks: fakeLocks() })
    const doFetch = vi.fn(async () => okResponse())
    const outcomes = await Promise.all(
      Array.from({ length: 5 }, () => refreshSessionShared(doFetch))
    )
    expect(doFetch).toHaveBeenCalledTimes(1)
    for (const o of outcomes) expect(o.ok).toBe(true)
  })

  it('a tab that waited for another tab reuses its refresh', async () => {
    vi.stubGlobal('navigator', { locks: fakeLocks() })
    // Another tab finished a refresh just now.
    window.localStorage.setItem(AUTH_REFRESH_AT_KEY, String(Date.now()))
    const doFetch = vi.fn(async () => okResponse())
    const outcome = await refreshSessionShared(doFetch)
    expect(outcome.ok).toBe(true)
    expect(doFetch).not.toHaveBeenCalled()
  })

  it('force refreshes even right after another tab', async () => {
    vi.stubGlobal('navigator', { locks: fakeLocks() })
    window.localStorage.setItem(AUTH_REFRESH_AT_KEY, String(Date.now()))
    const doFetch = vi.fn(async () => okResponse())
    const outcome = await refreshSessionShared(doFetch, { force: true })
    expect(doFetch).toHaveBeenCalledTimes(1)
    expect(outcome.accessToken).toBe('new-access')
  })

  it('after a 401 the dead refresh token is not presented again', async () => {
    vi.stubGlobal('navigator', { locks: fakeLocks() })
    const doFetch = vi.fn(
      async () =>
        new Response(JSON.stringify({ success: false, error: { code: 'REFRESH_TOKEN_REUSED' } }), {
          status: 401,
        })
    )
    const first = await refreshSessionShared(doFetch)
    const second = await refreshSessionShared(doFetch)
    expect(doFetch).toHaveBeenCalledTimes(1)
    expect(first).toMatchObject({ ok: false, status: 401, code: 'REFRESH_TOKEN_REUSED' })
    expect(second).toEqual(first)
  })

  it('a network error is retried on the next call', async () => {
    vi.stubGlobal('navigator', { locks: fakeLocks() })
    const doFetch = vi
      .fn<() => Promise<Response>>()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce(okResponse())
    expect((await refreshSessionShared(doFetch)).ok).toBe(false)
    expect((await refreshSessionShared(doFetch)).ok).toBe(true)
    expect(doFetch).toHaveBeenCalledTimes(2)
  })
})
