/**
 * Scope page parts (research/53 W1/W3): the In scope and Out of scope lists
 * ask for the right statuses (pending ones live on Approvals); Approvals
 * shows entries and exclusions together, never lets the requester approve,
 * and approves several at once; a new exclusion needs a reason.
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
    ([] as string[])
      .concat(p)
      .every(
        (x) =>
          (x !== actual.Permission.ScopeApprove &&
            x !== actual.Permission.ScopeExclusionsApprove) ||
          perms.approve
      )
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
vi.mock('@/hooks/use-display-user', () => ({
  useDisplayUser: () => ({ id: 'me', name: 'Me', email: 'me@acme.io' }),
}))
vi.mock('@/features/organization/api/use-members', () => ({
  useMembers: () => ({ members: [], isLoading: false }),
}))
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const { ScopeApprovals, approveBlocker } = await import('../scope-approvals')
const { ScopeEntriesTable } = await import('../scope-entries-table')
const { ScopeExclusionDialog, daysFromNow } = await import('../scope-exclusion-dialog')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const pendingEntry = {
  id: 'e1',
  pattern: '*.globex.io',
  target_type: 'domain',
  covers: 'domain_and_subdomains',
  status: 'pending',
  created_by: 'someone',
  created_at: '2026-10-07T10:00:00Z',
  approvals: [],
  approvals_required: 1,
  reason: 'dev env',
}
const mine = { ...pendingEntry, id: 'e2', pattern: 'mine.net', covers: 'name', created_by: 'me' }
const pendingExclusion = {
  id: 'x1',
  pattern: 'pay.acme.io',
  exclusion_type: 'domain',
  status: 'pending',
  created_by: 'someone',
  created_at: '2026-10-07T09:00:00Z',
  reason: 'PCI',
}

beforeEach(() => {
  api.get.mockReset()
  api.post.mockReset()
  toast.success.mockReset()
  perms.approve = true
})

function routeGets(entries: unknown[], exclusions: unknown[]) {
  api.get.mockImplementation((url: string) =>
    Promise.resolve(
      url.includes('/scope/settings')
        ? { effective_widening_approvals: 1, one_off_max_days: 7 }
        : url.includes('/scope/exclusions')
          ? { total: exclusions.length, data: exclusions }
          : { total: entries.length, data: entries }
    )
  )
}

describe('Approvals', () => {
  it('lists pending entries and exclusions, oldest first, and keeps the requester from approving', async () => {
    routeGets([pendingEntry, mine], [pendingExclusion])
    wrap(<ScopeApprovals />)
    const items = await screen.findAllByRole('listitem')
    expect(items[0]).toHaveTextContent('pay.acme.io')
    expect(items[0]).toHaveTextContent('Puts out of scope')
    const mineItem = screen.getByText('mine.net').closest('li')!
    expect(within(mineItem).getByRole('button', { name: /Approve/ })).toBeDisabled()
    expect(within(mineItem).getByText(/another approver must approve it/)).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/scope/targets?statuses=pending')
    )
    expect(api.get).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/scope/exclusions?statuses=pending')
    )
  })

  it('approves every selected change through its own route', async () => {
    routeGets([pendingEntry], [pendingExclusion])
    api.post.mockResolvedValue({ status: 'active' })
    const user = userEvent.setup()
    wrap(<ScopeApprovals />)
    await user.click(await screen.findByLabelText('Select every change you may approve'))
    await user.click(screen.getByRole('button', { name: /Approve selected \(2\)/ }))
    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/targets/e1/approve', {})
      expect(api.post).toHaveBeenCalledWith('/api/v1/scope/exclusions/x1/approve', {})
    })
    expect(toast.success).toHaveBeenCalledWith('2 changes approved')
  })

  it('says why approval is blocked', () => {
    const c = { kind: 'entry' as const, id: 'e1', item: pendingEntry }
    expect(approveBlocker(c, 'me', { entries: false, exclusions: true })).toMatch(
      /Only a scope approver/
    )
    expect(approveBlocker(c, 'other', { entries: true, exclusions: true })).toBeNull()
    expect(
      approveBlocker(
        { ...c, item: { ...pendingEntry, approvals: [{ user_id: 'other' }] } },
        'other',
        {
          entries: true,
          exclusions: true,
        }
      )
    ).toMatch(/already approved/)
  })
})

describe('In scope list', () => {
  it('asks for active, expired and inactive entries (pending live on Approvals)', async () => {
    routeGets([], [])
    wrap(
      <ScopeEntriesTable
        query={{ search: '', kind: 'all', status: 'all', page: 1, perPage: 20 }}
        searchInput=""
        onSearchInput={() => {}}
        onKindChange={() => {}}
        onStatusChange={() => {}}
        onPagination={() => {}}
        emptyAction={<p>onboarding</p>}
      />
    )
    expect(await screen.findByText('onboarding')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith(
      '/api/v1/scope/targets?statuses=active%2Cexpired%2Cinactive&page=1&per_page=20'
    )
  })

  it('a kind filter matches older stored types too', async () => {
    routeGets([], [])
    wrap(
      <ScopeEntriesTable
        query={{ search: '', kind: 'domain', status: 'active', page: 1, perPage: 20 }}
        searchInput=""
        onSearchInput={() => {}}
        onKindChange={() => {}}
        onStatusChange={() => {}}
        onPagination={() => {}}
      />
    )
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith(
        expect.stringContaining(
          'types=domain%2Csubdomain%2Cemail_domain%2Ccertificate&statuses=active'
        )
      )
    )
  })
})

describe('Put out of scope', () => {
  it('needs a reason and sends the detected kind and an end date', async () => {
    routeGets([], [])
    api.post.mockResolvedValue({ pattern: 'pay.acme.io', status: 'pending' })
    const user = userEvent.setup()
    wrap(<ScopeExclusionDialog open onOpenChange={() => {}} />)
    await user.type(screen.getByLabelText('What'), '203.0.113.0/24')
    expect(screen.getByText(/Detected: IP range/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Request exclusion' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/Say why/)
    await user.type(screen.getByLabelText('Reason'), 'partner')
    await user.type(screen.getByLabelText('Ends after (days, optional)'), '30')
    await user.click(screen.getByRole('button', { name: 'Request exclusion' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith(
        '/api/v1/scope/exclusions',
        expect.objectContaining({
          exclusion_type: 'ip_range',
          pattern: '203.0.113.0/24',
          reason: 'partner',
        })
      )
    )
    expect(api.post.mock.calls[0][1].expires_at).toBeTruthy()
    expect(daysFromNow(1, Date.parse('2026-10-07T00:00:00Z'))).toBe('2026-10-08T00:00:00.000Z')
  })
})
