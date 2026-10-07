/**
 * Scope policy (RFC-054 §6.3): approvers edit the knobs, everyone else reads
 * them; the values in effect are read-only and nothing turns scope off.
 * Scope entries (§6.1): each row says what it covers and whether it
 * authorizes now; another approver approves a pending entry in place.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
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
const { ScopeTargetsPanel } = await import('../scope-targets-panel')

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

describe('ScopeTargetsPanel', () => {
  const entries = {
    total: 3,
    data: [
      {
        id: 'e1',
        pattern: '*.acme.io',
        target_type: 'domain',
        covers: 'domain_and_subdomains',
        status: 'active',
        max_tier: 't1',
        reason: 'our domain',
      },
      {
        id: 'e2',
        pattern: 'promo.net',
        target_type: 'domain',
        covers: 'name',
        status: 'pending',
        created_by: 'someone-else',
        approvals: [],
        approvals_required: 1,
        expires_at: new Date(Date.now() + 5 * 86_400_000).toISOString(),
        reason: 'campaign',
      },
      {
        id: 'e3',
        pattern: 'mine.net',
        target_type: 'domain',
        covers: 'name',
        status: 'pending',
        created_by: 'me',
        approvals: [],
        approvals_required: 1,
      },
    ],
  }
  const query = { search: '', type: 'all', status: 'all', page: 1, perPage: 20 }
  const noop = () => {}

  it('shows coverage, status and expiry; approve only on what someone else asked for', async () => {
    api.get.mockImplementation((url: string) =>
      Promise.resolve(url.includes('/settings') ? settings : entries)
    )
    api.post.mockResolvedValue({ status: 'active' })
    const user = userEvent.setup()
    wrap(
      <ScopeTargetsPanel
        query={query}
        searchInput=""
        onSearchInput={noop}
        onTypeChange={noop}
        onStatusChange={noop}
        onPagination={noop}
      />
    )
    const acme = (await screen.findByText('*.acme.io')).closest('tr')!
    expect(within(acme).getByText('Covers acme.io and every name below it')).toBeInTheDocument()
    expect(within(acme).getByText('Active')).toBeInTheDocument()

    const promo = screen.getByText('promo.net').closest('tr')!
    expect(within(promo).getByText('Pending approval')).toBeInTheDocument()
    expect(within(promo).getByText('0 of 1 approvals')).toBeInTheDocument()
    expect(within(promo).getAllByText(/Expires in 5 days/).length).toBeGreaterThan(0)

    const mine = screen.getByText('mine.net').closest('tr')!
    expect(within(mine).queryByRole('button', { name: /Approve/ })).not.toBeInTheDocument()
    expect(within(mine).getByText(/another approver must approve/)).toBeInTheDocument()

    await user.click(within(promo).getByRole('button', { name: /Approve/ }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets/e2/approve', {})
    )
  })

  it('filters by status on the wire as `statuses`', async () => {
    api.get.mockImplementation((url: string) =>
      Promise.resolve(url.includes('/settings') ? settings : { total: 0, data: [] })
    )
    wrap(
      <ScopeTargetsPanel
        query={{ ...query, status: 'pending', type: 'domain' }}
        searchInput=""
        onSearchInput={noop}
        onTypeChange={noop}
        onStatusChange={noop}
        onPagination={noop}
      />
    )
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith(
        '/api/v1/scope/targets?types=domain&statuses=pending&page=1&per_page=20'
      )
    )
  })
})
