import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  RELOAD_STORAGE_KEY,
  RELOAD_WINDOW_MS,
  handleActionNotFound,
  installDeploymentSkewGuard,
  isActionNotFound,
} from '../deployment-skew'

function memStore() {
  const m = new Map<string, string>()
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => void m.set(k, v),
    has: () => m.has(RELOAD_STORAGE_KEY),
  }
}

const notFound = () =>
  new Response('', { status: 404, headers: { 'x-nextjs-action-not-found': '1' } })
const now = (fn: () => void) => fn()

describe('deployment skew guard', () => {
  afterEach(() => vi.restoreAllMocks())

  it('recognises only the 404 with the action-not-found marker', () => {
    expect(isActionNotFound(notFound())).toBe(true)
    expect(isActionNotFound(new Response('', { status: 404 }))).toBe(false)
    const ok = new Response('', { status: 200, headers: { 'x-nextjs-action-not-found': '1' } })
    expect(isActionNotFound(ok)).toBe(false)
  })

  it('notifies and reloads once, then not again inside the window (no loop)', () => {
    const reload = vi.fn()
    const notify = vi.fn()
    let t = 1_000_000
    const deps = { storage: memStore(), reload, notify, delay: now, now: () => t }
    expect(handleActionNotFound(deps)).toBe(true)
    expect(handleActionNotFound(deps)).toBe(false)
    expect(reload).toHaveBeenCalledTimes(1)
    expect(notify).toHaveBeenCalledTimes(1)
    t += RELOAD_WINDOW_MS + 1
    expect(handleActionNotFound(deps)).toBe(true)
    expect(reload).toHaveBeenCalledTimes(2)
  })

  it('still reloads when storage is unavailable', () => {
    const reload = vi.fn()
    expect(handleActionNotFound({ storage: null, reload, notify: vi.fn(), delay: now })).toBe(true)
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('wraps window.fetch: a stale server action response triggers the reload', async () => {
    const original = vi.fn().mockResolvedValue(notFound())
    window.fetch = original as unknown as typeof fetch
    const reload = vi.fn()
    const restore = installDeploymentSkewGuard({
      storage: memStore(),
      reload,
      notify: vi.fn(),
      delay: now,
    })
    const res = await window.fetch('/login', { method: 'POST' })
    expect(res.status).toBe(404)
    expect(reload).toHaveBeenCalledTimes(1)
    restore()
    expect(window.fetch).toBe(original)
  })

  it('leaves ordinary responses alone', async () => {
    window.fetch = vi.fn().mockResolvedValue(new Response('ok')) as unknown as typeof fetch
    const reload = vi.fn()
    const restore = installDeploymentSkewGuard({
      storage: memStore(),
      reload,
      notify: vi.fn(),
      delay: now,
    })
    await window.fetch('/x')
    expect(reload).not.toHaveBeenCalled()
    restore()
  })
})
