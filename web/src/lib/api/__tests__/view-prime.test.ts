import { beforeEach, describe, expect, it, vi } from 'vitest'
import {
  PRIME_TTL_MS,
  clearPrimedViews,
  installPrimedFetch,
  primeView,
  primedCount,
  takePrimed,
} from '../view-prime'

// A page view answers the page's own reads: each answer once, for a few
// seconds, only for a same-origin GET of the exact URL, and only the statuses
// a panel handles itself (200, 403, 404).

const F = '/api/v1/findings/f-1'

describe('view-prime', () => {
  beforeEach(() => clearPrimedViews())

  it('serves a primed answer once, with its status and body', async () => {
    primeView({
      parts: {
        [F]: { status: 200, body: { id: 'f-1' } },
        [`${F}/approvals`]: { status: 403, body: { code: 'FORBIDDEN', message: 'no' } },
      },
    })
    const ok = takePrimed(F)
    expect(ok?.status).toBe(200)
    expect(await ok?.json()).toEqual({ id: 'f-1' })
    expect(takePrimed(F)).toBeUndefined()
    const refused = takePrimed(`${F}/approvals`)
    expect(refused?.status).toBe(403)
    expect(await refused?.json()).toMatchObject({ code: 'FORBIDDEN' })
  })

  it('keeps neither a 401, a server failure nor a URL outside the API', () => {
    primeView({
      parts: {
        [`${F}/identity`]: { status: 500 },
        [`${F}/comments`]: { status: 401 },
        '/elsewhere': { status: 200, body: {} },
        'https://evil.example/api/v1/x': { status: 200, body: {} },
      },
    })
    expect(primedCount()).toBe(0)
  })

  it('expires answers and drops them on a session change', () => {
    primeView({ parts: { [F]: { status: 200, body: {} } } }, 0)
    expect(takePrimed(F, PRIME_TTL_MS + 1)).toBeUndefined()
    primeView({ parts: { [F]: { status: 200, body: {} } } })
    clearPrimedViews()
    expect(takePrimed(F)).toBeUndefined()
  })

  it('answers a same-origin GET from the primed view and sends everything else', async () => {
    const network = vi.fn(async () => new Response('{"from":"network"}', { status: 200 }))
    const win = {
      fetch: network,
      location: { origin: 'https://app.example' },
    } as unknown as Window & typeof globalThis
    installPrimedFetch(win)
    installPrimedFetch(win) // once only
    primeView({
      parts: {
        [F]: { status: 200, body: { from: 'view' } },
        [`${F}/retests`]: { status: 200, body: { from: 'view' } },
      },
    })

    expect(await (await win.fetch(F)).json()).toEqual({ from: 'view' })
    expect(network).not.toHaveBeenCalled()
    // Served once: the next read of the same URL goes to the server.
    await win.fetch(F)
    expect(network).toHaveBeenCalledTimes(1)
    // A write is never answered from the view.
    await win.fetch(`${F}/retests`, { method: 'POST', body: '{}' })
    expect(network).toHaveBeenCalledTimes(2)
    // An absolute same-origin URL is the same read.
    expect(await (await win.fetch(`https://app.example${F}/retests`)).json()).toEqual({
      from: 'view',
    })
    // Another origin is never answered from the view.
    primeView({ parts: { [F]: { status: 200, body: { from: 'view' } } } })
    await win.fetch(`https://other.example${F}`)
    expect(network).toHaveBeenCalledTimes(3)
  })
})
