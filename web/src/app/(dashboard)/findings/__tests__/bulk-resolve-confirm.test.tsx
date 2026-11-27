/**
 * Bulk "Resolved" closes every selected finding: it asks first and states the
 * count; one click on the menu item changes nothing.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const csrfFetch = vi.hoisted(() => vi.fn())
const post = vi.hoisted(() => vi.fn())
// The list's total: above the page's rows, "Select all N that match" is offered.
const mockTotal = vi.hoisted(() => ({ value: 2 }))
const del = vi.hoisted(() => vi.fn())
vi.mock('@/lib/api/client', async (orig) => ({
  ...(await orig<typeof import('@/lib/api/client')>()),
  csrfFetch,
  post,
  del,
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const routerPush = vi.fn()

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: routerPush, replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/findings',
  useSearchParams: () => new URLSearchParams(window.location.search),
}))

vi.mock('swr', () => ({
  default: vi.fn(() => ({ data: undefined, error: undefined, isLoading: false, mutate: vi.fn() })),
  mutate: vi.fn(),
  useSWRConfig: () => ({ mutate: vi.fn() }),
}))

vi.mock('@/features/findings/api/use-findings-api', () => ({
  useFindingApi: () => ({ data: undefined }),
  useFindingsApi: () => ({
    data: {
      data: [
        {
          id: 'f1',
          title: 'Outdated TLS',
          severity: 'high',
          status: 'confirmed',
          created_at: '2026-10-01T00:00:00Z',
          updated_at: '2026-10-01T00:00:00Z',
        },
        {
          id: 'f2',
          title: 'Open admin panel',
          severity: 'critical',
          status: 'confirmed',
          created_at: '2026-10-01T00:00:00Z',
          updated_at: '2026-10-01T00:00:00Z',
        },
      ],
      total: mockTotal.value,
      page: 1,
      per_page: 20,
    },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  useFindingStatsApi: () => ({
    data: { total: 0, by_severity: {}, by_status: {}, open_count: 0 },
    isLoading: false,
    mutate: vi.fn(),
  }),
  buildFindingsExportUrl: () => '#',
  buildFindingsEndpoint: () => '/api/v1/findings',
  fetchFindings: vi.fn(),
  invalidateFindingsCache: vi.fn(),
}))

vi.mock('@/features/findings/api/use-finding-groups', async (orig) => ({
  ...(await orig<typeof import('@/features/findings/api/use-finding-groups')>()),
  useFindingGroups: () => ({
    data: {
      data: [
        {
          group_key: '10114',
          group_type: 'rule',
          label: 'ICMP Timestamp Request',
          severity: 'low',
          metadata: {},
          stats: {
            total: 3,
            open: 3,
            in_progress: 0,
            fix_applied: 0,
            resolved: 0,
            affected_assets: 3,
          },
        },
      ],
      pagination: { total: 1, page: 1, per_page: 20 },
    },
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
}))

vi.mock('@/features/config/api/finding-source-api', () => ({
  useFindingSourcesApi: () => ({ data: undefined }),
  groupFindingSourcesByCategory: () => [],
}))
let denied = new Set<string>()
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => !denied.has(p) }),
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => true,
}))
vi.mock('@/features/saved-views/components/saved-views-menu', () => ({
  SavedViewsMenu: () => null,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/features/findings/components/auto-assign-dialog', () => ({
  AutoAssignDialog: () => null,
}))
vi.mock('@/features/findings/components/mark-fixed-dialog', () => ({ MarkFixedDialog: () => null }))
vi.mock('@/features/findings/components/create-ticket-dialog', () => ({
  CreateTicketDialog: () => null,
}))
vi.mock('@/features/remediation-hub/components/add-findings-to-task-dialog', () => ({
  AddFindingsToTaskDialog: () => null,
}))
vi.mock('@/features/findings', async (orig) => ({
  ...(await orig<typeof import('@/features/findings')>()),
  FindingDetailDrawer: () => null,
  CreateFindingDialog: () => null,
}))
vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAsset: () => ({ asset: null, isLoading: false, error: undefined }),
}))
vi.mock('@/features/components/api/hooks', () => ({
  useComponentVersion: () => ({
    data: { name: 'log4j-core', version: '2.14.1' },
    isLoading: false,
  }),
}))

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', slug: 't1' } }),
}))
vi.mock('@/features/findings/components/assignee-select', () => ({
  AssigneeSelect: ({ onChange }: { onChange: (u: { id: string; name: string }) => void }) => (
    <button type="button" onClick={() => onChange({ id: 'u1', name: 'Ada Lovelace' })}>
      Pick Ada
    </button>
  ),
}))
// The dry run of the API's transition engine: f2 is blocked unless allowAll.
let allowAll = true
const evaluate = vi.hoisted(() => vi.fn())
vi.mock('@/features/findings/api/use-finding-transitions', () => ({
  evaluateFindingTransitions: evaluate,
}))
evaluate.mockImplementation(async (ids: string[], to: string) =>
  ids.map((id) =>
    allowAll || id === 'f1'
      ? { finding_id: id, decision: { to, allowed: true } }
      : { finding_id: id, decision: { to, allowed: false, blocked: [{ code: 'not_fix_owner' }] } }
  )
)

vi.mock('@/features/findings/filters/contract', async (orig) => ({
  ...(await orig<typeof import('@/features/findings/filters/contract')>()),
  useFindingFilterContract: () => ({ contract: undefined, isLoading: false, error: undefined }),
}))
vi.mock('@/features/saved-views/api/use-saved-views', async (orig) => ({
  ...(await orig<typeof import('@/features/saved-views/api/use-saved-views')>()),
  useSavedViews: () => ({ views: [], error: undefined, isLoading: false, mutate: vi.fn() }),
}))

vi.mock('@/features/findings/api/use-quick-views', () => ({
  useFindingQuickViews: () => ({ data: undefined }),
  refreshFindingQuickViews: vi.fn(),
}))

import FindingsPage from '../page'
import { enter } from '@/test/user-input'

// No per-action timer hop: each hop waits a whole macrotask, which a busy machine stretches.
let user: ReturnType<typeof userEvent.setup>
beforeEach(() => {
  user = userEvent.setup({ delay: null })
})

describe('Findings bulk resolve', () => {
  it('asks before resolving the selected findings', async () => {
    post.mockResolvedValue({ updated: 2, failed: 0 })
    window.history.replaceState(null, '', '/findings')
    render(<FindingsPage />)
    await user.click(screen.getAllByRole('checkbox', { name: /select all/i })[0])
    const bar = screen.getByRole('toolbar', { name: 'Actions for selected rows' })
    await user.click(within(bar).getByRole('button', { name: 'Set status' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Resolved' }))

    const bulkCalls = () =>
      post.mock.calls.filter(([url]) => String(url).includes('/findings/bulk/status'))
    expect(bulkCalls()).toHaveLength(0)
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Resolve 2 findings?')

    // A bulk resolve is attested: the confirm waits for a note.
    expect(within(dialog).getByRole('button', { name: 'Resolve 2 findings' })).toBeDisabled()
    fireEvent.change(within(dialog).getByLabelText('Note (required)'), {
      target: { value: 'patched in 4.2' },
    })
    await user.click(within(dialog).getByRole('button', { name: 'Resolve 2 findings' }))
    await waitFor(() => expect(bulkCalls()).toHaveLength(1))
    expect(bulkCalls()[0][1]).toMatchObject({
      finding_ids: ['f1', 'f2'],
      status: 'resolved',
      resolution: 'patched in 4.2',
    })
  })
  it('asks before a bulk status move, with the count and the finding titles', async () => {
    allowAll = true
    post.mockClear()
    post.mockResolvedValue({ updated: 2, failed: 0 })
    window.history.replaceState(null, '', '/findings')
    render(<FindingsPage />)
    await user.click(screen.getAllByRole('checkbox', { name: /select all/i })[0])
    const bar = screen.getByRole('toolbar', { name: 'Actions for selected rows' })
    await user.click(within(bar).getByRole('button', { name: 'Set status' }))
    await user.click(await screen.findByRole('menuitem', { name: 'In progress' }))
    const bulkCalls = () =>
      post.mock.calls.filter(([url]) => String(url).includes('/findings/bulk/status'))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Mark 2 findings as In progress?')
    expect(dialog).toHaveTextContent('Outdated TLS')
    expect(dialog).toHaveTextContent('Open admin panel')
    expect(bulkCalls()).toHaveLength(0)

    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(bulkCalls()).toHaveLength(0)

    await user.click(within(bar).getByRole('button', { name: 'Set status' }))
    await user.click(await screen.findByRole('menuitem', { name: 'In progress' }))
    await user.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', {
        name: 'Mark 2 findings In progress',
      })
    )
    await waitFor(() => expect(bulkCalls()).toHaveLength(1))
    expect(bulkCalls()[0][1]).toMatchObject({ finding_ids: ['f1', 'f2'], status: 'in_progress' })
  })

  it('asks before a bulk assignment and names the assignee', async () => {
    post.mockClear()
    post.mockResolvedValue({ updated: 2, failed: 0 })
    window.history.replaceState(null, '', '/findings')
    render(<FindingsPage />)
    await user.click(screen.getAllByRole('checkbox', { name: /select all/i })[0])
    await user.click(screen.getByRole('button', { name: 'Pick Ada' }))
    const assignCalls = () =>
      post.mock.calls.filter(([url]) => String(url).includes('/findings/bulk/assign'))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Assign 2 findings to Ada Lovelace?')
    expect(assignCalls()).toHaveLength(0)
    await user.click(within(dialog).getByRole('button', { name: 'Assign 2 findings' }))
    await waitFor(() => expect(assignCalls()).toHaveLength(1))
    expect(assignCalls()[0][1]).toMatchObject({ finding_ids: ['f1', 'f2'], user_id: 'u1' })
  })

  it('sends only the findings the dry run allows', async () => {
    allowAll = false
    post.mockClear()
    post.mockResolvedValue({ updated: 1, failed: 0 })
    window.history.replaceState(null, '', '/findings')
    render(<FindingsPage />)
    await user.click(screen.getAllByRole('checkbox', { name: /select all/i })[0])
    const bar = screen.getByRole('toolbar', { name: 'Actions for selected rows' })
    await user.click(within(bar).getByRole('button', { name: 'Set status' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Resolved' }))
    const dialog = await screen.findByRole('alertdialog')
    fireEvent.change(within(dialog).getByLabelText('Note (required)'), {
      target: { value: 'patched in 4.2' },
    })
    await user.click(within(dialog).getByRole('button', { name: 'Resolve 2 findings' }))
    const bulkCalls = () =>
      post.mock.calls.filter(([url]) => String(url).includes('/findings/bulk/status'))
    await waitFor(() => expect(bulkCalls()).toHaveLength(1))
    expect(bulkCalls()[0][1].finding_ids).toEqual(['f1'])
  })

  it('keeps the note and the dialog when the bulk resolve fails', async () => {
    allowAll = true
    post.mockClear()
    post.mockRejectedValue(new Error('Failed to update findings'))
    window.history.replaceState(null, '', '/findings')
    render(<FindingsPage />)
    await user.click(screen.getAllByRole('checkbox', { name: /select all/i })[0])
    const bar = screen.getByRole('toolbar', { name: 'Actions for selected rows' })
    await user.click(within(bar).getByRole('button', { name: 'Set status' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Resolved' }))
    const dialog = await screen.findByRole('alertdialog')
    fireEvent.change(within(dialog).getByLabelText('Note (required)'), {
      target: { value: 'patched in 4.2' },
    })
    await user.click(within(dialog).getByRole('button', { name: 'Resolve 2 findings' }))
    await waitFor(() =>
      expect(
        post.mock.calls.filter(([url]) => String(url).includes('/findings/bulk/status'))
      ).toHaveLength(1)
    )
    expect(await screen.findByRole('alertdialog')).toBeInTheDocument()
    expect(screen.getByLabelText('Note (required)')).toHaveValue('patched in 4.2')
  })

  it('deletes a finding only after its title is typed', async () => {
    del.mockClear()
    del.mockResolvedValue(undefined)
    window.history.replaceState(null, '', '/findings')
    render(<FindingsPage />)
    await user.click(screen.getByRole('button', { name: 'Actions for Outdated TLS' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Delete the finding "Outdated TLS"?')
    const confirm = within(dialog).getByRole('button', { name: 'Delete finding' })
    expect(confirm).toBeDisabled()
    await enter(user, within(dialog).getByRole('textbox'), 'Outdated TLS')
    await user.click(confirm)
    await waitFor(() => expect(del).toHaveBeenCalledTimes(1))
    expect(String(del.mock.calls[0][0])).toContain('/api/v1/findings/f1')
  })

  it('offers no selection or bulk bar without findings:bulk_update', () => {
    denied = new Set(['findings:bulk_update', 'findings:remediation:write'])
    window.history.replaceState(null, '', '/findings')
    render(<FindingsPage />)
    expect(screen.queryAllByRole('checkbox', { name: /select all/i })).toHaveLength(0)
    expect(screen.queryByRole('toolbar', { name: 'Actions for selected rows' })).toBeNull()
    denied = new Set()
  })

  it('hides the status menu without findings:status', async () => {
    denied = new Set(['findings:status'])
    window.history.replaceState(null, '', '/findings')
    render(<FindingsPage />)
    await user.click(screen.getAllByRole('checkbox', { name: /select all/i })[0])
    const bar = screen.getByRole('toolbar', { name: 'Actions for selected rows' })
    expect(within(bar).queryByRole('button', { name: 'Set status' })).toBeNull()
    denied = new Set()
  })

  it('applies a status to every finding that matches through the server, with the count', async () => {
    mockTotal.value = 418
    allowAll = true
    post.mockClear()
    post.mockResolvedValue({
      operation: {
        id: 'op1',
        status: 'succeeded',
        total: 418,
        succeeded: 418,
        skipped: 0,
        failed: 0,
      },
    })
    window.history.replaceState(null, '', '/findings?severity=critical')
    try {
      render(<FindingsPage />)
      await user.click(screen.getAllByRole('checkbox', { name: /select all/i })[0])
      const bar = screen.getByRole('toolbar', { name: 'Actions for selected rows' })
      await user.click(within(bar).getByRole('button', { name: 'Select all 418 that match' }))
      expect(within(bar).getByText('All 418 that match are selected')).toBeInTheDocument()
      await user.click(within(bar).getByRole('button', { name: 'Set status' }))
      await user.click(await screen.findByRole('menuitem', { name: 'In progress' }))
      const dialog = await screen.findByRole('alertdialog')
      expect(dialog).toHaveTextContent('Mark 418 findings as In progress?')
      // The server re-checks every finding in the caller's scope; the dialog says so.
      expect(within(dialog).getByTestId('bulk-preview')).toHaveTextContent('in your data scope')
      await user.click(within(dialog).getByRole('button', { name: /Mark 418 findings/ }))
      const byFilter = () =>
        post.mock.calls.filter(([url]) => String(url).includes('/bulk/by-filter/status'))
      await waitFor(() => expect(byFilter()).toHaveLength(1))
      const body = byFilter()[0][1]
      expect(body).toMatchObject({ status: 'in_progress', expected_count: 418 })
      expect(body.filter).not.toHaveProperty('page')
      expect(body.filter).not.toHaveProperty('per_page')
      expect(body.filter).not.toHaveProperty('sort')
      // Ids are never sent for a filter selection.
      expect(body).not.toHaveProperty('finding_ids')
    } finally {
      mockTotal.value = 2
    }
  })
})
