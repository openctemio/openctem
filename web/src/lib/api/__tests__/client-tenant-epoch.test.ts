/**
 * The API client sends nothing built from an organization the tab has left:
 * after another tab switched the session, a write (a bulk action on the old
 * organization's selection) is refused before it leaves the browser, and a
 * read still in flight when the organization changes ends as TENANT_CHANGED,
 * not as a timeout.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { env } from '@/lib/env'

let client: typeof import('@/lib/api/client')
let epoch: typeof import('@/lib/tenant-epoch')

function setTenantCookie(id: string | null) {
  document.cookie =
    id === null
      ? `${env.cookies.tenant}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`
      : `${env.cookies.tenant}=${encodeURIComponent(JSON.stringify({ id }))}; path=/`
}

beforeEach(async () => {
  vi.resetModules()
  client = await import('@/lib/api/client')
  epoch = await import('@/lib/tenant-epoch')
  epoch.resetTenantEpochForTests()
  epoch.setActiveTenantId('org-a')
  setTenantCookie('org-a')
})
afterEach(() => {
  vi.unstubAllGlobals()
  setTenantCookie(null)
})

describe('apiClient and the organization epoch', () => {
  it('refuses a write after another tab moved the session to another organization', async () => {
    const fetchSpy = vi.fn(async () => new Response('{}', { status: 200 }))
    vi.stubGlobal('fetch', fetchSpy)
    setTenantCookie('org-b')

    await expect(
      client.post('/api/v1/findings/bulk/status', { ids: ['finding-of-a'], status: 'resolved' })
    ).rejects.toMatchObject({ code: 'TENANT_CHANGED' })
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('ends a read of the old organization as TENANT_CHANGED', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (_url: RequestInfo | URL, init?: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () =>
              reject(new DOMException('aborted', 'AbortError'))
            )
          })
      )
    )
    const read = client.get('/api/v1/findings?page=5')
    epoch.endTenantEpoch()
    await expect(read).rejects.toMatchObject({ code: 'TENANT_CHANGED' })
  })

  it('sends requests normally while the session is the tab organization', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response('{"ok":true}', {
            status: 200,
            headers: { 'content-type': 'application/json' },
          })
      )
    )
    await expect(client.get('/api/v1/findings')).resolves.toEqual({ ok: true })
  })
})
