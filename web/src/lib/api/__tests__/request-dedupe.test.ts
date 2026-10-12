import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { coalesceGet, resetRequestDedupe } from '../request-dedupe'

function deferred<T>() {
  let resolve!: (v: T) => void
  let reject!: (e: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

describe('coalesceGet', () => {
  beforeEach(() => resetRequestDedupe())
  afterEach(() => {
    vi.unstubAllEnvs()
    vi.restoreAllMocks()
  })

  it('sends one request for two callers of the same URL in flight', async () => {
    const d = deferred<{ n: number }>()
    const run = vi.fn(() => d.promise)
    const a = coalesceGet('/api/v1/x', run)
    const b = coalesceGet('/api/v1/x', run)
    d.resolve({ n: 1 })
    await expect(a).resolves.toEqual({ n: 1 })
    await expect(b).resolves.toEqual({ n: 1 })
    expect(run).toHaveBeenCalledTimes(1)
  })

  it('does not share different URLs', async () => {
    const run = vi.fn(async () => 1)
    await Promise.all([coalesceGet('/api/v1/x', run), coalesceGet('/api/v1/y', run)])
    expect(run).toHaveBeenCalledTimes(2)
  })

  it('sends a new request once the previous one settled', async () => {
    const run = vi.fn(async () => 1)
    await coalesceGet('/api/v1/x', run)
    await coalesceGet('/api/v1/x', run)
    expect(run).toHaveBeenCalledTimes(2)
  })

  it('shares a failure and then lets the next call retry', async () => {
    const d = deferred<number>()
    const run = vi.fn(() => d.promise)
    const a = coalesceGet('/api/v1/x', run)
    const b = coalesceGet('/api/v1/x', run)
    d.reject(new Error('boom'))
    await expect(a).rejects.toThrow('boom')
    await expect(b).rejects.toThrow('boom')
    const ok = vi.fn(async () => 2)
    await expect(coalesceGet('/api/v1/x', ok)).resolves.toBe(2)
  })

  it('warns in development when the same GET is in flight twice', async () => {
    vi.stubEnv('NODE_ENV', 'development')
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const d = deferred<number>()
    const a = coalesceGet('/api/v1/x', () => d.promise)
    const b = coalesceGet('/api/v1/x', () => d.promise)
    d.resolve(1)
    await Promise.all([a, b])
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('[request-budget]'))
    expect(warn.mock.calls[0][0]).toContain('/api/v1/x')
  })

  it('warns in development when a GET repeats right after its answer', async () => {
    vi.stubEnv('NODE_ENV', 'development')
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    await coalesceGet('/api/v1/x', async () => 1)
    await coalesceGet('/api/v1/x', async () => 1)
    expect(warn).toHaveBeenCalledTimes(1)
  })

  it('is silent in production', async () => {
    vi.stubEnv('NODE_ENV', 'production')
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const d = deferred<number>()
    const a = coalesceGet('/api/v1/x', () => d.promise)
    const b = coalesceGet('/api/v1/x', () => d.promise)
    d.resolve(1)
    await Promise.all([a, b])
    expect(warn).not.toHaveBeenCalled()
  })

  it('never shares a request on the server, where callers are different users', async () => {
    const win = globalThis.window
    // @ts-expect-error simulate the server runtime
    delete globalThis.window
    try {
      const run = vi.fn(async () => 1)
      await Promise.all([coalesceGet('/api/v1/x', run), coalesceGet('/api/v1/x', run)])
      expect(run).toHaveBeenCalledTimes(2)
    } finally {
      globalThis.window = win
    }
  })
})
