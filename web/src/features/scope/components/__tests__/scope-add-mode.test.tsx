/**
 * A member's scope change says what will happen: it applies at once unless
 * the organization runs Strict scan approval, where it is a request.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, renderHook, screen, waitFor } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ approve: false, write: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  const can = (p: string) =>
    p === actual.Permission.ScopeApprove
      ? perms.approve
      : p === actual.Permission.ScopeWrite
        ? perms.write
        : true
  return { ...actual, useHasPermission: can, usePermissions: () => ({ can }) }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }))
vi.mock('@/hooks/use-display-user', () => ({ useDisplayUser: () => ({ id: 'u-me' }) }))

const { useScopeAddMode } = await import('../../api/use-scope-api')
const { ScopeFixButtons } = await import('../scope-check-results')

const wrapper = ({ children }: { children: ReactNode }) => (
  <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
)
const settings = (strict: boolean, oneOff = 'admins_and_requests') => ({
  one_off_targets: oneOff,
  one_off_max_days: 7,
  approval_policy: { entries_need_approval: strict },
})
const requestFix = [
  { action: 'request_access', pattern: 'promo.example.com', target_type: 'domain', days: 7 },
]

beforeEach(() => {
  api.get.mockReset()
  perms.approve = false
  perms.write = true
})

describe('useScopeAddMode', () => {
  it('a member adds directly when scan approval is not Strict', async () => {
    api.get.mockResolvedValue(settings(false, 'admins'))
    const { result } = renderHook(() => useScopeAddMode(), { wrapper })
    await waitFor(() => expect(result.current.settings).toBeDefined())
    expect(result.current.isRequest).toBe(false)
    expect(result.current.canAdd).toBe(true)
  })

  it('a member requests under Strict, and only when requests are accepted', async () => {
    api.get.mockResolvedValue(settings(true))
    const { result } = renderHook(() => useScopeAddMode(), { wrapper })
    await waitFor(() => expect(result.current.settings).toBeDefined())
    expect(result.current.isRequest).toBe(true)
    expect(result.current.canAdd).toBe(true)

    api.get.mockResolvedValue(settings(true, 'admins'))
    const closed = renderHook(() => useScopeAddMode(), { wrapper })
    await waitFor(() => expect(closed.result.current.settings).toBeDefined())
    expect(closed.result.current.canAdd).toBe(false)
  })

  it('an approver adds directly under Strict; no scope:write adds nothing', async () => {
    perms.approve = true
    api.get.mockResolvedValue(settings(true))
    const { result } = renderHook(() => useScopeAddMode(), { wrapper })
    await waitFor(() => expect(result.current.settings).toBeDefined())
    expect(result.current.isRequest).toBe(false)
    perms.write = false
    const none = renderHook(() => useScopeAddMode(), { wrapper })
    expect(none.result.current.canAdd).toBe(false)
  })
})

describe('ScopeFixButtons for a member', () => {
  it('names the fix "Allow for 7 days" when it applies at once', async () => {
    api.get.mockResolvedValue(settings(false))
    render(<ScopeFixButtons fixes={requestFix} />, { wrapper })
    expect(await screen.findByRole('button', { name: 'Allow for 7 days' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Request access' })).not.toBeInTheDocument()
  })

  it('names it "Request access" under Strict scan approval', async () => {
    api.get.mockResolvedValue(settings(true))
    render(<ScopeFixButtons fixes={requestFix} />, { wrapper })
    await waitFor(() => expect(api.get).toHaveBeenCalled())
    expect(await screen.findByRole('button', { name: 'Request access' })).toBeInTheDocument()
  })
})
