import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  CLIENT_ERRORS_ENDPOINT,
  classifyError,
  installClientErrorListeners,
  reportClientError,
  resetClientErrorThrottle,
} from '@/lib/client-errors'

describe('client error reporting', () => {
  let beacon: ReturnType<typeof vi.fn>

  beforeEach(() => {
    resetClientErrorThrottle()
    beacon = vi.fn(async () => new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', beacon)
    document.cookie = 'csrf_token=page-token; path=/'
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
    document.cookie = 'csrf_token=; max-age=0; path=/'
  })

  async function sentBodies(): Promise<unknown[]> {
    return beacon.mock.calls.map(([, init]) => JSON.parse((init as RequestInit).body as string))
  }

  it('classifies chunk-load failures, including the module factory error after a deploy', () => {
    const cases = [
      Object.assign(new Error('Loading chunk 123 failed.'), { name: 'ChunkLoadError' }),
      new Error('Failed to fetch dynamically imported module: https://x/_next/static/chunks/a.js'),
      new Error(
        'Module 1234 was instantiated because it was required from module 5678, but the module factory is not available.'
      ),
    ]
    for (const err of cases) expect(classifyError(err, 'render')).toBe('chunk_load')
    expect(classifyError(new TypeError('x is undefined'), 'render')).toBe('render')
    expect(classifyError('plain string', 'unhandled')).toBe('unhandled')
  })

  it('sends only the kind: no message, stack, URL or user detail', async () => {
    reportClientError('render')
    expect(beacon).toHaveBeenCalledTimes(1)
    expect(beacon.mock.calls[0][0]).toBe(CLIENT_ERRORS_ENDPOINT)
    expect(await sentBodies()).toEqual([{ kind: 'render' }])
  })

  it('sends the CSRF header and survives a reload (keepalive)', () => {
    reportClientError('render')
    const init = beacon.mock.calls[0][1] as RequestInit
    expect(init).toMatchObject({ method: 'POST', keepalive: true })
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('page-token')
  })

  it('throttles: one report per kind a minute, ten per page', () => {
    const t0 = 1_000_000
    expect(reportClientError('render', t0)).toBe(true)
    expect(reportClientError('render', t0 + 1_000)).toBe(false)
    expect(reportClientError('render', t0 + 61_000)).toBe(true)
    for (let i = 0; i < 20; i++)
      reportClientError(i % 2 ? 'unhandled' : 'other', t0 + 200_000 + i * 61_000)
    expect(beacon.mock.calls.length).toBe(10)
  })

  it('reports uncaught errors and rejections, and stops after cleanup', async () => {
    const remove = installClientErrorListeners()
    window.dispatchEvent(new ErrorEvent('error', { message: 'boom' }))
    const rejection = new Event('unhandledrejection') as PromiseRejectionEvent
    Object.defineProperty(rejection, 'reason', {
      value: new Error('Importing a module script failed.'),
    })
    window.dispatchEvent(rejection)
    expect(await sentBodies()).toEqual([{ kind: 'unhandled' }, { kind: 'chunk_load' }])

    remove()
    resetClientErrorThrottle()
    window.dispatchEvent(new ErrorEvent('error', { message: 'after' }))
    expect(beacon).toHaveBeenCalledTimes(2)
  })

  it('never throws when the request fails', () => {
    beacon.mockImplementation(() => {
      throw new Error('offline')
    })
    expect(() => reportClientError('other')).not.toThrow()
  })
})
