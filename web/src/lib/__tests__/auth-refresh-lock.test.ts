import { afterEach, describe, expect, it, vi } from 'vitest'

import { AUTH_REFRESH_LOCK, withAuthRefreshLock } from '../auth-refresh-lock'

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
