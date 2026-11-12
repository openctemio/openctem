/**
 * TenantProvider.switchTeam ends the organization epoch: reads in flight are
 * aborted, the old organization's browser state is dropped, other tabs are
 * told, and the epoch number the dashboard keys its tree on increases. A
 * switch made in another tab is adopted the same way.
 */
import * as React from 'react'
import { act, render, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const toastInfo = vi.fn()
vi.mock('sonner', () => ({ toast: { info: (m: string) => toastInfo(m), success: vi.fn() } }))

const MEMBERSHIPS = [
  { id: 'org-a', name: 'Org A', slug: 'org-a', role: 'member' },
  { id: 'org-b', name: 'Org B', slug: 'org-b', role: 'admin' },
]
vi.mock('@/lib/api/user-tenant-hooks', () => ({
  useMyTenants: () => ({
    data: MEMBERSHIPS,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  invalidateMyTenantsCache: vi.fn(),
}))

const posted: unknown[] = []
class FakeChannel {
  onmessage: ((e: MessageEvent) => void) | null = null
  postMessage(m: unknown) {
    posted.push(m)
  }
  close() {}
}

import { TenantProvider, useTenant } from '@/context/tenant-provider'
import { env } from '@/lib/env'
import {
  TENANT_CHANGED_EVENT,
  getActiveTenantId,
  resetTenantEpochForTests,
  tenantRequestSignal,
} from '@/lib/tenant-epoch'

function setTenantCookie(id: string) {
  const org = MEMBERSHIPS.find((m) => m.id === id)!
  document.cookie = `${env.cookies.tenant}=${encodeURIComponent(
    JSON.stringify({ id, slug: org.slug, name: org.name, role: org.role })
  )}; path=/`
}

let ctx: ReturnType<typeof useTenant> | null = null
function Probe() {
  const value = useTenant()
  React.useEffect(() => {
    ctx = value
  })
  return null
}

beforeEach(() => {
  resetTenantEpochForTests()
  posted.length = 0
  toastInfo.mockReset()
  localStorage.clear()
  sessionStorage.clear()
  vi.stubGlobal('BroadcastChannel', FakeChannel)
  setTenantCookie('org-a')
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      // The switch-team route sets the new session cookie in its response.
      setTenantCookie('org-b')
      return new Response(
        JSON.stringify({ data: { tenant_id: 'org-b', tenant_slug: 'org-b', role: 'admin' } }),
        { status: 200, headers: { 'content-type': 'application/json' } }
      )
    })
  )
})
afterEach(() => {
  vi.unstubAllGlobals()
  document.cookie = `${env.cookies.tenant}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`
})

async function mountWithTenantA() {
  render(
    <TenantProvider>
      <Probe />
    </TenantProvider>
  )
  await waitFor(() => expect(ctx?.currentTenant?.id).toBe('org-a'))
  act(() => ctx!.loadTenants())
  await waitFor(() => expect(ctx?.tenants.length).toBe(2))
}

describe('TenantProvider organization epoch', () => {
  it("a switch ends A's epoch: reads aborted, A's state dropped, other tabs told", async () => {
    await mountWithTenantA()
    expect(getActiveTenantId()).toBe('org-a')
    sessionStorage.setItem('openctem.findings.triage', '{"ids":["finding-of-a"]}')
    sessionStorage.setItem('openctem:settings-return-to', '/findings?page=5')
    const readOfA = tenantRequestSignal('GET')!

    await act(async () => {
      await ctx!.switchTeam('org-b')
    })

    expect(readOfA.aborted).toBe(true)
    expect(ctx!.currentTenant?.id).toBe('org-b')
    expect(getActiveTenantId()).toBe('org-b')
    expect(ctx!.epoch).toBe(1)
    expect(ctx!.epochKeepsLocation).toBe(false)
    expect(sessionStorage.getItem('openctem.findings.triage')).toBeNull()
    expect(sessionStorage.getItem('openctem:settings-return-to')).toBeNull()
    expect(posted).toEqual([{ tenantId: 'org-b' }])
    // This tab's own switch is not "another tab".
    expect(toastInfo).not.toHaveBeenCalled()
  })

  it('a link that names the organization keeps the address', async () => {
    await mountWithTenantA()
    await act(async () => {
      await ctx!.switchTeam('org-b', { keepLocation: true })
    })
    expect(ctx!.epoch).toBe(1)
    expect(ctx!.epochKeepsLocation).toBe(true)
  })

  it('a failed switch changes nothing', async () => {
    await mountWithTenantA()
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response('{"error":{"code":"FORBIDDEN"}}', { status: 403 }))
    )
    const readOfA = tenantRequestSignal('GET')!
    await act(async () => {
      await expect(ctx!.switchTeam('org-b')).rejects.toThrow()
    })
    expect(ctx!.epoch).toBe(0)
    expect(readOfA.aborted).toBe(false)
    expect(getActiveTenantId()).toBe('org-a')
  })

  it('adopts a switch made in another tab before sending anything else', async () => {
    await mountWithTenantA()
    // Tab 2 switched: the shared session cookie now names B.
    setTenantCookie('org-b')
    // Tab 1 tries to submit a bulk action built from A's selection.
    expect(() => tenantRequestSignal('POST')).toThrow()
    await waitFor(() => expect(ctx!.currentTenant?.id).toBe('org-b'))
    expect(ctx!.epoch).toBe(1)
    expect(getActiveTenantId()).toBe('org-b')
    expect(toastInfo).toHaveBeenCalledWith(expect.stringContaining('Org B'))
    // Once adopted, requests flow again under B.
    expect(() => tenantRequestSignal('POST')).not.toThrow()
  })

  it('adopts on focus when the cookie changed while the tab was in the background', async () => {
    await mountWithTenantA()
    setTenantCookie('org-b')
    act(() => {
      window.dispatchEvent(new Event('focus'))
    })
    await waitFor(() => expect(ctx!.epoch).toBe(1))
    act(() => {
      window.dispatchEvent(new Event(TENANT_CHANGED_EVENT))
    })
    expect(ctx!.epoch).toBe(1)
  })
})
