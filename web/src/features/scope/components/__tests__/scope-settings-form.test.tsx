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
    usePermissions: () => ({ can: has, isOwner: () => false }),
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
  active_proof: 'platform_sensors' as const,
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
    expect(screen.getByText('Shared sensors need proof')).toBeInTheDocument()
    expect(screen.getByText('Always on')).toBeInTheDocument()
    // The switches are auto-join, confirm-adds-to-scope, the review gate and
    // the opt-in proof for CI scopes (none of them changes what may be
    // scanned); nothing else toggles.
    const switches = screen.getAllByRole('switch')
    expect(switches).toHaveLength(4)
    expect(switches[0]).toHaveAccessibleName('Add discovered names automatically')
    expect(switches[1]).toHaveAccessibleName('Confirming an asset adds it to scope')
    expect(switches[1]).toBeChecked()
    expect(switches[2]).toHaveAccessibleName('Review discovered assets first')
    expect(switches[2]).not.toBeChecked()
    expect(switches[3]).toHaveAccessibleName('Require proof for CI scopes')
    expect(switches[3]).not.toBeChecked()
    expect(screen.queryByText(/disable scope|turn scope off/i)).not.toBeInTheDocument()
  })

  it('saves the whole policy; the default approval count goes as null', async () => {
    api.put.mockResolvedValue({ ...settings, auto_join_discovered: false })
    const user = userEvent.setup()
    wrap(<ScopeSettingsForm settings={settings} />)
    const save = screen.getByRole('button', { name: /Save changes/ })
    expect(save).toBeDisabled()
    await user.click(screen.getByRole('switch', { name: 'Add discovered names automatically' }))
    await user.click(save)
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/v1/scope/settings', {
        auto_join_discovered: false,
        confirm_adds_to_scope: true,
        review_before_inventory: false,
        one_off_targets: 'admins_and_requests',
        one_off_max_days: 7,
        widening_approvals: null,
        default_max_tier: 't1',
        ci_scope_requires_proof: false,
      })
    )
  })

  it('turns off adding a confirmed asset to scope', async () => {
    api.put.mockResolvedValue({ ...settings, confirm_adds_to_scope: false })
    const user = userEvent.setup()
    wrap(<ScopeSettingsForm settings={settings} />)
    await user.click(screen.getByRole('switch', { name: 'Confirming an asset adds it to scope' }))
    await user.click(screen.getByRole('button', { name: /Save changes/ }))
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith(
        '/api/v1/scope/settings',
        expect.objectContaining({ confirm_adds_to_scope: false })
      )
    )
  })

  it('keeps the review gate on request (RFC-054 §15)', async () => {
    api.put.mockResolvedValue({ ...settings, review_before_inventory: true })
    const user = userEvent.setup()
    wrap(<ScopeSettingsForm settings={settings} />)
    await user.click(screen.getByRole('switch', { name: 'Review discovered assets first' }))
    await user.click(screen.getByRole('button', { name: /Save changes/ }))
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith(
        '/api/v1/scope/settings',
        expect.objectContaining({ review_before_inventory: true })
      )
    )
  })

  it('sets what unclassified assets get (RFC-054 §16)', async () => {
    Element.prototype.scrollIntoView ??= () => {}
    api.put.mockResolvedValue({ ...settings, unclassified_scans: 'full' })
    const user = userEvent.setup()
    wrap(
      <ScopeSettingsForm
        settings={
          {
            ...settings,
            unclassified_scans: 'low_impact',
            unclassified_scans_effective: 'low_impact',
          } as typeof settings
        }
      />
    )
    const select = screen.getByRole('combobox', { name: 'Scan unclassified assets' })
    expect(select).toHaveTextContent('Low-impact (default)')
    expect(
      screen.getByText(/get low-impact checks: common ports at a low rate/)
    ).toBeInTheDocument()
    await user.click(select)
    await user.click(await screen.findByRole('option', { name: 'Full' }))
    await user.click(screen.getByRole('button', { name: /Save changes/ }))
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith(
        '/api/v1/scope/settings',
        expect.objectContaining({ unclassified_scans: 'full' })
      )
    )
  })

  it('says the setting is off while Strict scan approval is in force', () => {
    wrap(
      <ScopeSettingsForm
        settings={
          {
            ...settings,
            unclassified_scans: 'full',
            unclassified_scans_effective: 'off',
          } as typeof settings
        }
      />
    )
    expect(
      screen.getByText(/Strict scan approval is in force, so this is Off for now/)
    ).toBeInTheDocument()
  })

  it('turns automatic coverage off (RFC-093)', async () => {
    api.put.mockResolvedValue({ ...settings, auto_coverage: false, auto_coverage_effective: false })
    const user = userEvent.setup()
    wrap(
      <ScopeSettingsForm
        settings={{ ...settings, auto_coverage_effective: true } as typeof settings}
      />
    )
    const sw = screen.getByRole('switch', { name: 'Automatic coverage' })
    expect(sw).toBeChecked()
    await user.click(sw)
    await user.click(screen.getByRole('button', { name: /Save changes/ }))
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith(
        '/api/v1/scope/settings',
        expect.objectContaining({ auto_coverage: false })
      )
    )
  })

  it('says automatic coverage waits for the organization under Strict approval', () => {
    wrap(
      <ScopeSettingsForm
        settings={
          {
            ...settings,
            auto_coverage_effective: false,
            approval_policy: { scan_approval: 'strict' },
          } as typeof settings
        }
      />
    )
    expect(screen.getByRole('switch', { name: 'Automatic coverage' })).not.toBeChecked()
    expect(screen.getByText(/so it is off until you turn it on/)).toBeInTheDocument()
  })

  it('leaves automatic coverage untouched when the API does not report it', async () => {
    api.put.mockResolvedValue(settings)
    const user = userEvent.setup()
    wrap(<ScopeSettingsForm settings={settings} />)
    expect(screen.queryByRole('switch', { name: 'Automatic coverage' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('switch', { name: 'Review discovered assets first' }))
    await user.click(screen.getByRole('button', { name: /Save changes/ }))
    await waitFor(() => expect(api.put).toHaveBeenCalled())
    expect(api.put.mock.calls[0][1]).not.toHaveProperty('auto_coverage')
  })

  it('shows no unclassified setting when the API does not report it', () => {
    wrap(<ScopeSettingsForm settings={settings} />)
    expect(
      screen.queryByRole('combobox', { name: 'Scan unclassified assets' })
    ).not.toBeInTheDocument()
  })

  it('is read-only without scope:approve', () => {
    perms.approve = false
    wrap(<ScopeSettingsForm settings={settings} />)
    expect(screen.queryByRole('button', { name: /Save changes/ })).not.toBeInTheDocument()
    for (const sw of screen.getAllByRole('switch')) expect(sw).toBeDisabled()
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
