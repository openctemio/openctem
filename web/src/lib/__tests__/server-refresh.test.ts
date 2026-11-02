import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  refreshSessionOnce,
  resetServerRefreshFlights,
  SETTLED_REFRESH_TTL_MS,
  type ServerRefreshResult,
} from '../server-refresh'

const ok = (token: string): ServerRefreshResult => ({
  ok: true,
  status: 200,
  accessToken: `access-${token}`,
  refreshToken: `rotated-${token}`,
  expiresIn: 900,
  tenantId: 't1',
  tenantSlug: 'org',
  role: 'member',
})

function deferred<T>() {
  let resolve!: (v: T) => void
  const promise = new Promise<T>((r) => (resolve = r))
  return { promise, resolve }
}

describe('refreshSessionOnce', () => {
  afterEach(() => {
    resetServerRefreshFlights()
    vi.useRealTimers()
  })

  it('parallel calls with one refresh token make one API refresh and share its result', async () => {
    const gate = deferred<ServerRefreshResult>()
    const call = vi.fn(() => gate.promise)
    const calls = Array.from({ length: 6 }, () => refreshSessionOnce('rt-a', 't1', call))
    gate.resolve(ok('a'))
    const results = await Promise.all(calls)
    expect(call).toHaveBeenCalledTimes(1)
    for (const r of results) expect(r).toEqual(ok('a'))
  })

  it('a late call with the old token within the window gets the same rotated pair', async () => {
    const call = vi.fn(async () => ok('a'))
    await refreshSessionOnce('rt-a', 't1', call)
    const late = await refreshSessionOnce('rt-a', 't1', call)
    expect(call).toHaveBeenCalledTimes(1)
    expect(late).toEqual(ok('a'))
  })

  it('after the window the token is presented to the API again', async () => {
    vi.useFakeTimers()
    const call = vi.fn(async () => ok('a'))
    await refreshSessionOnce('rt-a', 't1', call)
    vi.advanceTimersByTime(SETTLED_REFRESH_TTL_MS + 1)
    await refreshSessionOnce('rt-a', 't1', call)
    expect(call).toHaveBeenCalledTimes(2)
  })

  it('a 401 is not retried with the same dead token', async () => {
    const call = vi.fn(async (): Promise<ServerRefreshResult> => ({
      ok: false,
      status: 401,
      code: 'REFRESH_TOKEN_REUSED',
    }))
    await refreshSessionOnce('rt-dead', 't1', call)
    const again = await refreshSessionOnce('rt-dead', 't1', call)
    expect(call).toHaveBeenCalledTimes(1)
    expect(again).toMatchObject({ ok: false, status: 401, code: 'REFRESH_TOKEN_REUSED' })
  })

  it('a transient failure is not remembered', async () => {
    const call = vi
      .fn<() => Promise<ServerRefreshResult>>()
      .mockResolvedValueOnce({ ok: false, status: 502 })
      .mockResolvedValueOnce(ok('a'))
    expect((await refreshSessionOnce('rt-a', 't1', call)).ok).toBe(false)
    expect((await refreshSessionOnce('rt-a', 't1', call)).ok).toBe(true)
    expect(call).toHaveBeenCalledTimes(2)
  })

  it('never shares a result between different refresh tokens or organizations', async () => {
    const call = vi.fn(async (token: string) => ok(token))
    const [a, b, aOther] = await Promise.all([
      refreshSessionOnce('rt-a', 't1', call),
      refreshSessionOnce('rt-b', 't1', call),
      refreshSessionOnce('rt-a', 't2', call),
    ])
    expect(call).toHaveBeenCalledTimes(3)
    expect(a).toEqual(ok('rt-a'))
    expect(b).toEqual(ok('rt-b'))
    expect(aOther).toEqual(ok('rt-a'))
  })

  it('is shared by every module instance of the process (globalThis)', async () => {
    const call = vi.fn(async () => ok('a'))
    await refreshSessionOnce('rt-a', 't1', call)
    vi.resetModules()
    const fresh = await import('../server-refresh')
    await fresh.refreshSessionOnce('rt-a', 't1', call)
    expect(call).toHaveBeenCalledTimes(1)
  })
})
