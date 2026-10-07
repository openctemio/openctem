/**
 * Adding to scope (RFC-054 §6.1): an approver adds an entry (the domain and
 * every name below it by default); a member only requests one name for a few
 * days, with a reason. The server's codes come back as sentences.
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
  return {
    ...actual,
    useHasPermission: (p: string) => p !== actual.Permission.ScopeApprove || perms.approve,
    usePermissions: () => ({ can: () => true }),
  }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { ScopeEntryDialog, isSingleTarget, approvalsForNew } = await import('../scope-entry-dialog')

const settings = {
  auto_join_discovered: true,
  one_off_targets: 'admins_and_requests',
  one_off_max_days: 7,
  widening_approvals: null,
  default_max_tier: 't1',
  effective_widening_approvals: 1,
  admin_count: 2,
  active_proof: 'off',
}

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

beforeEach(() => {
  api.get.mockReset().mockResolvedValue(settings)
  api.post.mockReset()
  toast.success.mockReset()
  perms.approve = true
})

describe('ScopeEntryDialog', () => {
  it('an approver adds the domain and every name below it by default', async () => {
    api.post.mockResolvedValue({ pattern: '*.acme.io', status: 'pending', approvals_required: 1 })
    const user = userEvent.setup()
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    await user.type(await screen.findByLabelText('Domain'), 'acme.io')
    expect(screen.getByText('acme.io and every name below it · permanent')).toBeInTheDocument()
    expect(screen.getByText(/Needs 1 approval from another approver/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets', {
        target_type: 'domain',
        pattern: '*.acme.io',
        description: undefined,
        reason: undefined,
        max_tier: 't1',
      })
    )
    expect(toast.success).toHaveBeenCalledWith(
      '*.acme.io is waiting for approval',
      expect.anything()
    )
  })

  it('typing *.x picks "x and every name below it"; "only" stores the exact name', async () => {
    api.post.mockResolvedValue({ pattern: 'acme.io', status: 'active' })
    const user = userEvent.setup()
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    const input = await screen.findByLabelText('Domain')
    await user.type(input, '*.acme.io')
    expect(input).toHaveValue('acme.io')
    await user.click(screen.getByText('acme.io only'))
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/scope/targets',
        expect.objectContaining({ pattern: 'acme.io' })
      )
    )
  })

  it('a one-off from a fix needs a reason and sends its days', async () => {
    api.post.mockResolvedValue({ pattern: 'promo.net', status: 'active' })
    const user = userEvent.setup()
    wrap(
      <ScopeEntryDialog
        open
        onOpenChange={() => {}}
        draft={{ target_type: 'domain', pattern: 'promo.net', duration: 'one_off', days: 5 }}
      />
    )
    await screen.findByDisplayValue('promo.net')
    await user.click(screen.getByText('promo.net only'))
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/Say why this target may be probed/)
    expect(api.post).not.toHaveBeenCalled()
    await user.type(screen.getByLabelText('Reason'), 'MKT-9')
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/scope/targets',
        expect.objectContaining({ pattern: 'promo.net', expires_in_days: 5, reason: 'MKT-9' })
      )
    )
  })

  it('a member requests one name for a few days, never a wildcard', async () => {
    perms.approve = false
    api.post.mockResolvedValue({ pattern: 'shop.acme.io', status: 'pending' })
    const user = userEvent.setup()
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    expect(await screen.findByRole('heading', { name: 'Request access' })).toBeInTheDocument()
    // No coverage or duration choice: a request is one name, one-off.
    expect(screen.queryByText('Covers')).not.toBeInTheDocument()
    expect(screen.queryByText('Permanent')).not.toBeInTheDocument()
    await user.type(screen.getByLabelText('Domain'), '*.acme.io')
    await user.type(screen.getByLabelText('Reason'), 'need it')
    await user.click(screen.getByRole('button', { name: 'Send request' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/one name or address/)
    expect(api.post).not.toHaveBeenCalled()

    await user.clear(screen.getByLabelText('Domain'))
    await user.type(screen.getByLabelText('Domain'), 'shop.acme.io')
    await user.click(screen.getByRole('button', { name: 'Send request' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/scope/targets',
        expect.objectContaining({ pattern: 'shop.acme.io', expires_in_days: 7, reason: 'need it' })
      )
    )
    expect(toast.success).toHaveBeenCalledWith('Request sent', expect.anything())
  })

  it('a member sees why they cannot request when the organization does not accept requests', async () => {
    perms.approve = false
    api.get.mockResolvedValue({ ...settings, one_off_targets: 'admins' })
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    expect(
      await screen.findByText('Your organization does not accept scope requests from members.')
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Send request' })).not.toBeInTheDocument()
  })

  it('shows the server refusal as a sentence', async () => {
    api.post.mockRejectedValue(Object.assign(new Error('raw'), { code: 'PUBLIC_SUFFIX' }))
    const user = userEvent.setup()
    wrap(<ScopeEntryDialog open onOpenChange={() => {}} />)
    await user.type(await screen.findByLabelText('Domain'), 'com.vn')
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/public suffix/i)
  })
})

describe('request and approval rules', () => {
  it('single names only for requests', () => {
    expect(isSingleTarget('domain', 'shop.acme.io')).toBe(true)
    expect(isSingleTarget('domain', '*.acme.io')).toBe(false)
    expect(isSingleTarget('ip_address', '203.0.113.7')).toBe(true)
    expect(isSingleTarget('ip_range', '203.0.113.0/24')).toBe(false)
  })

  it('a request needs at least one approval; t2 always one', () => {
    expect(approvalsForNew({ canApprove: false, effective: 0, tier: 't1' })).toBe(1)
    expect(approvalsForNew({ canApprove: true, effective: 0, tier: 't1' })).toBe(0)
    expect(approvalsForNew({ canApprove: true, effective: 0, tier: 't2' })).toBe(1)
    expect(approvalsForNew({ canApprove: true, effective: 2, tier: 't1' })).toBe(2)
  })
})
