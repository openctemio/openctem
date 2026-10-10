/**
 * A target behind a pending scope entry (RFC-054 §7): the requester never
 * gets Approve; they see who can approve and may remind them, and only the
 * sole owner with nobody else to approve gets the self-approval. Every other
 * blocker (tier, domain proof) is listed with its action.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ approve: true, write: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return {
    ...actual,
    useHasPermission: (p: string) =>
      p === actual.Permission.ScopeApprove
        ? perms.approve
        : p === actual.Permission.ScopeWrite
          ? perms.write
          : true,
    usePermissions: () => ({ can: () => true, isOwner: () => false }),
  }
})
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => ({ moduleIds: ['attack_surface'], isLoading: false }),
}))
vi.mock('@/hooks/use-display-user', () => ({ useDisplayUser: () => ({ id: 'u-me' }) }))
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { ScopePendingEntry, pendingBlockers, proofNeededFor } =
  await import('../scope-pending-entry')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const entry = (over: Record<string, unknown> = {}) => ({
  id: 'e1',
  pattern: '*.vndirect.com.vn',
  target_type: 'domain',
  status: 'pending',
  max_tier: 't1',
  created_by: { id: 'u-me' },
  approvals: [],
  approval: {
    remaining: 1,
    eligible_approver_count: 2,
    eligible_approvers: [
      { kind: 'user', id: 'a', name: 'Lan' },
      { kind: 'user', id: 'b', name: 'Minh' },
    ],
    self_approval_available: false,
  },
  ...over,
})

function serve(e: ReturnType<typeof entry>, settings: Record<string, unknown> = {}) {
  api.get.mockImplementation(async (url: string) => {
    if (url === '/api/v1/scope/targets/e1') return e
    if (url.startsWith('/api/v1/easm/verified-domains')) return { data: [] }
    return { active_proof: 'off', ...settings }
  })
}

beforeEach(() => {
  api.get.mockReset()
  api.post.mockReset()
  perms.approve = true
  perms.write = true
})

describe('ScopePendingEntry', () => {
  it('the requester gets no Approve: who can approve, and Remind approvers', async () => {
    serve(entry())
    api.post.mockResolvedValue({ reminded: 2 })
    const user = userEvent.setup()
    wrap(<ScopePendingEntry entryId="e1" />)
    expect(
      await screen.findByText(/You asked for \*\.vndirect\.com\.vn, so another approver/)
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve the entry' })).toBeNull()
    expect(screen.queryByRole('button', { name: /only owner/ })).toBeNull()
    expect(screen.getByTestId('pending-approvers')).toHaveTextContent('Can approve: Lan, Minh.')
    await user.click(screen.getByRole('button', { name: /Remind approvers/ }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets/e1/remind', {})
    )
  })

  it('without the member list, approvers are counted, not named', async () => {
    serve(
      entry({
        approval: { remaining: 1, eligible_approver_count: 3, self_approval_available: false },
      })
    )
    wrap(<ScopePendingEntry entryId="e1" />)
    expect(await screen.findByTestId('pending-approvers')).toHaveTextContent(
      '3 members can approve it.'
    )
  })

  it('the sole owner with nobody else to approve gets the self-approval', async () => {
    serve(
      entry({
        approval: { remaining: 1, eligible_approver_count: 0, self_approval_available: true },
      })
    )
    const user = userEvent.setup()
    wrap(<ScopePendingEntry entryId="e1" />)
    await user.click(await screen.findByRole('button', { name: 'Approve as the only owner' }))
    expect(screen.getByRole('dialog', { name: 'Approve your own entry' })).toBeInTheDocument()
    expect(screen.getByLabelText('Code from your authenticator app')).toBeInTheDocument()
    // Nobody to remind.
    expect(screen.queryByRole('button', { name: /Remind approvers/ })).toBeNull()
  })

  it('another approver gets Approve', async () => {
    serve(entry({ created_by: { id: 'u-other' } }))
    api.post.mockResolvedValue({ status: 'active' })
    const user = userEvent.setup()
    wrap(<ScopePendingEntry entryId="e1" />)
    await user.click(await screen.findByRole('button', { name: 'Approve the entry' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets/e1/approve', {})
    )
  })

  it('lists the tier and domain proof that still block, with their actions', async () => {
    serve(entry(), { active_proof: 'platform_sensors' })
    wrap(<ScopePendingEntry entryId="e1" probeTier={2} sensorPreference="auto" />)
    const box = await screen.findByTestId('pending-entry')
    expect(within(box).getByText('3 things left before it can be scanned:')).toBeInTheDocument()
    expect(within(box).getByText(/probes at T2 intrusive; the entry allows T1/)).toBeInTheDocument()
    expect(within(box).getByText(/controls vndirect\.com\.vn/)).toBeInTheDocument()
    expect(within(box).getByRole('button', { name: 'Verify domain' })).toBeInTheDocument()
  })

  it('shows nothing once the entry is no longer pending', async () => {
    serve(entry({ status: 'active' }))
    const { container } = wrap(<ScopePendingEntry entryId="e1" />)
    await waitFor(() => expect(api.get).toHaveBeenCalled())
    expect(container.querySelector('[data-testid="pending-entry"]')).toBeNull()
  })
})

describe('blocker rules', () => {
  it('approval always; tier when the entry allows less; proof when needed and missing', () => {
    expect(
      pendingBlockers({ entry: { max_tier: 't1' }, proofNeeded: false, proofVerified: false })
    ).toEqual(['approval'])
    expect(
      pendingBlockers({
        entry: { max_tier: 't1' },
        probeTier: 2,
        proofNeeded: true,
        proofVerified: true,
      })
    ).toEqual(['approval', 'tier'])
    expect(
      pendingBlockers({
        entry: { max_tier: 't2' },
        probeTier: 2,
        proofNeeded: true,
        proofVerified: false,
      })
    ).toEqual(['approval', 'proof'])
  })

  it('proof: intrusive always, platform sensors unless the scan uses our own', () => {
    expect(proofNeededFor('off', 2, 'tenant')).toBe(true)
    expect(proofNeededFor('off', 1, 'auto')).toBe(false)
    expect(proofNeededFor('all', 1, 'tenant')).toBe(true)
    expect(proofNeededFor('platform_sensors', 1, 'tenant')).toBe(false)
    expect(proofNeededFor('platform_sensors', 1, 'auto')).toBe(true)
  })
})
