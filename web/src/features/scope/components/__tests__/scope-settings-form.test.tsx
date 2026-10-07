/**
 * Scope policy (RFC-054 §6.3): approvers edit the knobs, everyone else reads
 * them; the values in effect are read-only and nothing turns scope off.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ approve: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  const has = (p: string | string[]) =>
    ([] as string[]).concat(p).every((x) => x !== actual.Permission.ScopeApprove || perms.approve)
  return {
    ...actual,
    useHasPermission: has,
    usePermissions: () => ({ can: has }),
    Can: ({ children }: { children: ReactNode }) => <>{children}</>,
  }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
vi.mock('@/stores/auth-store', async (orig) => ({
  ...(await orig<typeof import('@/stores/auth-store')>()),
  useUser: () => ({ id: 'me', email: 'me@acme.io', roles: [] }),
}))
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const { ScopeSettingsForm, effectiveApprovalsFor } = await import('../scope-settings-form')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const settings = {
  auto_join_discovered: true,
  one_off_targets: 'admins_and_requests',
  one_off_max_days: 7,
  widening_approvals: undefined,
  default_max_tier: 't1',
  effective_widening_approvals: 1,
  admin_count: 3,
  active_proof: 'platform_sensors',
}

beforeEach(() => {
  api.get.mockReset()
  api.post.mockReset()
  api.put.mockReset()
  toast.success.mockReset()
  perms.approve = true
})

describe('ScopeSettingsForm', () => {
  it('shows what is in effect, read-only, and offers no way to turn scope off', () => {
    wrap(<ScopeSettingsForm settings={settings} />)
    expect(screen.getByText('Platform sensors need proof')).toBeInTheDocument()
    expect(screen.getByText('Always on')).toBeInTheDocument()
    // The one switch is auto-join; nothing else toggles.
    const switches = screen.getAllByRole('switch')
    expect(switches).toHaveLength(1)
    expect(switches[0]).toHaveAccessibleName('Add discovered names automatically')
    expect(screen.queryByText(/disable scope|turn scope off/i)).not.toBeInTheDocument()
  })

  it('saves the whole policy; the default approval count goes as null', async () => {
    api.put.mockResolvedValue({ ...settings, auto_join_discovered: false })
    const user = userEvent.setup()
    wrap(<ScopeSettingsForm settings={settings} />)
    const save = screen.getByRole('button', { name: /Save changes/ })
    expect(save).toBeDisabled()
    await user.click(screen.getByRole('switch'))
    await user.click(save)
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/v1/scope/settings', {
        auto_join_discovered: false,
        one_off_targets: 'admins_and_requests',
        one_off_max_days: 7,
        widening_approvals: null,
        default_max_tier: 't1',
      })
    )
  })

  it('is read-only without scope:approve', () => {
    perms.approve = false
    wrap(<ScopeSettingsForm settings={settings} />)
    expect(screen.queryByRole('button', { name: /Save changes/ })).not.toBeInTheDocument()
    expect(screen.getByRole('switch')).toBeDisabled()
    expect(screen.getByText('Only scope approvers can change these.')).toBeInTheDocument()
  })

  it('computes the approvals hint the way the server does', () => {
    expect(effectiveApprovalsFor(null, 1)).toBe(0)
    expect(effectiveApprovalsFor(null, 3)).toBe(1)
    expect(effectiveApprovalsFor(0, 3)).toBe(1) // two or more admins: never 0
    expect(effectiveApprovalsFor(2, 2)).toBe(1) // capped at admins - 1
    expect(effectiveApprovalsFor(2, 5)).toBe(2)
  })
})
