/**
 * Approvals Page Tests
 *
 * Tests for the redesigned approval requests page:
 * - Loading state shows skeleton
 * - Error state shows full-page error with retry
 * - Empty state shows message
 * - Stats cards render with counts (CardHeader/CardTitle pattern)
 * - Tab filtering with counts
 * - DataTable renders with data
 * - Back link to findings page
 * - Refresh button
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { toast } from 'sonner'

// ============================================
// MOCKS
// ============================================

// The columns the page passes to the table, so a test can render one cell.
const captured = vi.hoisted(() => ({ columns: [] as unknown[] }))

const mockMutate = vi.fn()
const mockTriggerApprove = vi.fn()
const mockTriggerReject = vi.fn()
const mockTriggerCancel = vi.fn()

vi.mock('@/features/findings/api/use-findings-api', () => ({
  useApprovals: vi.fn(() => ({
    data: null,
    isLoading: true,
    error: null,
    mutate: mockMutate,
  })),
  useApproveStatus: vi.fn(() => ({
    trigger: mockTriggerApprove,
    isMutating: false,
  })),
  useRejectApproval: vi.fn(() => ({
    trigger: mockTriggerReject,
    isMutating: false,
  })),
  useCancelApproval: vi.fn(() => ({
    trigger: mockTriggerCancel,
    isMutating: false,
  })),
  remindApprovers: vi.fn(),
}))

// Group exceptions: the pending count and the panel's list.
const batchState = vi.hoisted(() => ({ pendingTotal: 0 }))
vi.mock('@/features/findings/api/use-approval-batches', () => ({
  useApprovalBatches: vi.fn((_page: number, perPage: number) =>
    perPage === 1
      ? {
          data: { data: [], total: batchState.pendingTotal, page: 1, per_page: 1 },
          mutate: vi.fn(),
        }
      : {
          data: {
            data: [
              {
                id: 'batch-1',
                source_type: 'task',
                source_id: 'task-1',
                source_title: 'Patch OpenSSL on edge hosts',
                requested_status: 'accepted',
                tier: 'security',
                approvals_required: 1,
                approvals_collected: 0,
                status: 'pending',
                decide_by: '2026-10-23T00:00:00Z',
                member_count: 3,
              },
            ],
            total: 1,
            page: 1,
            per_page: 20,
          },
          isLoading: false,
          mutate: vi.fn(),
        }
  ),
  useApprovalBatch: vi.fn(() => ({
    data: undefined,
    error: null,
    isLoading: false,
    mutate: vi.fn(),
  })),
  approvalBatchApi: { approve: vi.fn(), reject: vi.fn(), cancel: vi.fn() },
}))

vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => children,
  Permission: { FindingsApprove: 'findings:approve', FindingsWrite: 'findings:write' },
}))

vi.mock('@/hooks/use-display-user', () => ({ useDisplayUser: () => ({ id: 'user-1' }) }))

// The tab (status) and page live in the URL through useListParams.
const listState = vi.hoisted(() => ({ status: '', view: '', batch: '', setFilter: vi.fn() }))
vi.mock('@/hooks/use-list-params', () => ({
  useListParams: () => ({
    page: 1,
    perPage: 20,
    filters: { status: listState.status, view: listState.view, batch: listState.batch },
    pagination: { pageIndex: 0, pageSize: 20 },
    setPagination: vi.fn(),
    setFilter: listState.setFilter,
  }),
}))

vi.mock('@/features/findings/types', () => ({
  APPROVAL_STATUSES: ['pending', 'approved', 'rejected', 'canceled', 'expired'],
  APPROVAL_STATUS_CONFIG: {
    pending: { label: 'Pending', variant: 'warning' },
    approved: { label: 'Approved', variant: 'success' },
    rejected: { label: 'Rejected', variant: 'destructive' },
    canceled: { label: 'Canceled', variant: 'secondary' },
  },
  FINDING_STATUS_CONFIG: {
    false_positive: {
      label: 'False Positive',
      color: 'border-slate-500/50',
      bgColor: 'bg-slate-500/20',
      textColor: 'text-slate-400',
      icon: '',
      category: 'closed',
      requiresApproval: true,
    },
    accepted: {
      label: 'Risk Accepted',
      color: 'border-amber-500/50',
      bgColor: 'bg-amber-500/20',
      textColor: 'text-amber-400',
      icon: '',
      category: 'closed',
      requiresApproval: true,
    },
  },
}))

vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}))

vi.mock('@/lib/api/error-handler', () => ({
  getErrorMessage: vi.fn((_error, fallback) => fallback || 'Error'),
  ApiClientError: class ApiClientError extends Error {
    statusCode = 500
  },
}))

vi.mock('@/lib/utils', () => ({
  cn: (...args: unknown[]) => args.filter(Boolean).join(' '),
}))

vi.mock('@/features/shared/components/page-header', () => ({
  PageHeader: ({
    title,
    description,
    children,
  }: {
    title: string
    description?: string
    children?: React.ReactNode
  }) => (
    <div data-testid="page-header">
      <h1>{title}</h1>
      {description && <p>{description}</p>}
      {children}
    </div>
  ),
}))

vi.mock('@/features/shared/components/data-table/data-table', () => ({
  DataTable: ({
    data,
    columns,
    emptyMessage,
    emptyDescription,
  }: {
    data: unknown[]
    emptyMessage?: string
    emptyDescription?: string
    columns: unknown[]
    searchPlaceholder?: string
    searchKey?: string
    showColumnToggle?: boolean
    pageSize?: number
  }) => {
    captured.columns = columns
    return (
      <div data-testid="data-table">
        {data.length === 0 ? (
          <div>
            <p>{emptyMessage}</p>
            <p>{emptyDescription}</p>
          </div>
        ) : (
          <div data-testid="table-rows">
            {data.map((item: unknown, i: number) => (
              <div key={i} data-testid="table-row">
                {JSON.stringify(item)}
              </div>
            ))}
          </div>
        )}
      </div>
    )
  },
}))

vi.mock('@/features/shared/components/data-table/data-table-column-header', () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
}))

// Import after mocks
import ApprovalsPage from '../page'
import { useApprovals } from '@/features/findings/api/use-findings-api'

// ============================================
// MOCK DATA
// ============================================

const mockApprovals = [
  {
    id: 'approval-1',
    tenant_id: 'tenant-1',
    finding_id: 'finding-abc123def456',
    requested_status: 'false_positive',
    requested_by: 'user-1',
    justification: 'Code path is unreachable in production.',
    status: 'pending' as const,
    created_at: '2026-03-01T10:00:00Z',
  },
  {
    id: 'approval-2',
    tenant_id: 'tenant-1',
    finding_id: 'finding-xyz789abc012',
    requested_status: 'accepted',
    requested_by: 'user-2',
    justification: 'Risk accepted - legacy decommissioning.',
    status: 'approved' as const,
    approved_by: 'user-3',
    approved_at: '2026-03-02T12:00:00Z',
    expires_at: '2026-06-01T00:00:00Z',
    created_at: '2026-03-01T11:00:00Z',
  },
  {
    id: 'approval-3',
    tenant_id: 'tenant-1',
    finding_id: 'finding-def456ghi789',
    requested_status: 'false_positive',
    requested_by: 'user-1',
    justification: 'Test environment only.',
    status: 'rejected' as const,
    rejected_by: 'user-3',
    rejected_at: '2026-03-02T14:00:00Z',
    created_at: '2026-03-01T12:00:00Z',
  },
]

// The server counts every status under the caller's scope, not just the page.
const COUNTS = { pending: 1, approved: 1, rejected: 1, canceled: 0, expired: 0 }

function mockHook(
  overrides: Partial<{
    data: {
      data: typeof mockApprovals
      total: number
      page: number
      per_page: number
      status_counts?: Record<string, number>
    } | null
    isLoading: boolean
    error: Error | undefined
  }> = {}
) {
  vi.mocked(useApprovals).mockReturnValue({
    data: null,
    isLoading: false,
    error: undefined,
    mutate: mockMutate,
    isValidating: false,
    ...overrides,
  } as ReturnType<typeof useApprovals>)
}

// ============================================
// TESTS
// ============================================

describe('ApprovalsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // ============================================
  // PAGE HEADER & NAVIGATION
  // ============================================

  describe('page header', () => {
    it('renders the page title', () => {
      mockHook({ data: { data: [], total: 0, page: 1, per_page: 20, status_counts: {} } })
      render(<ApprovalsPage />)
      expect(screen.getByText('Approval requests')).toBeInTheDocument()
    })

    it('renders description with counts', () => {
      mockHook({
        data: { data: mockApprovals, total: 3, page: 1, per_page: 20, status_counts: COUNTS },
      })
      render(<ApprovalsPage />)
      expect(screen.getByText('3 requests, 1 waiting for a decision')).toBeInTheDocument()
    })

    it('shows loading description while fetching', () => {
      mockHook({ isLoading: true })
      render(<ApprovalsPage />)
      expect(screen.getByText('Loading approvals…')).toBeInTheDocument()
    })

    it('renders back link to findings page', () => {
      mockHook({ data: { data: [], total: 0, page: 1, per_page: 20, status_counts: {} } })
      render(<ApprovalsPage />)
      const backLink = screen.getByText('Back to Findings')
      expect(backLink.closest('a')).toHaveAttribute('href', '/findings')
    })

    it('renders refresh button', () => {
      mockHook({ data: { data: [], total: 0, page: 1, per_page: 20, status_counts: {} } })
      render(<ApprovalsPage />)
      expect(screen.getByText('Refresh')).toBeInTheDocument()
    })
  })

  // ============================================
  // LOADING STATE
  // ============================================

  describe('loading state', () => {
    it('shows skeleton when loading', () => {
      mockHook({ isLoading: true })
      const { container } = render(<ApprovalsPage />)
      const skeletons = container.querySelectorAll('[data-slot="skeleton"]')
      expect(skeletons.length).toBeGreaterThan(0)
    })
  })

  // ============================================
  // ERROR STATE
  // ============================================

  describe('error state', () => {
    it('shows full-page error with retry button', () => {
      mockHook({ error: new Error('Network error') })
      render(<ApprovalsPage />)
      expect(screen.getByText('Failed to load approvals')).toBeInTheDocument()
      expect(screen.getByText('Retry')).toBeInTheDocument()
    })

    it('calls mutate when retry is clicked', () => {
      mockHook({ error: new Error('Network error') })
      render(<ApprovalsPage />)
      fireEvent.click(screen.getByText('Retry'))
      expect(mockMutate).toHaveBeenCalled()
    })
  })

  // ============================================
  // EMPTY STATE
  // ============================================

  describe('empty state', () => {
    it('shows empty message when no approvals', () => {
      mockHook({ data: { data: [], total: 0, page: 1, per_page: 20, status_counts: {} } })
      render(<ApprovalsPage />)
      expect(screen.getByText('No approval requests')).toBeInTheDocument()
    })
  })

  // ============================================
  // STATS CARDS
  // ============================================

  describe('stats cards', () => {
    it('renders stats with CardDescription labels', () => {
      mockHook({
        data: { data: mockApprovals, total: 3, page: 1, per_page: 20, status_counts: COUNTS },
      })
      render(<ApprovalsPage />)

      // Stat labels. "Pending" is also a tab label now that the tab count is a
      // separate TabsCount, so it appears more than once.
      expect(screen.getAllByText('Pending').length).toBeGreaterThanOrEqual(1)
      expect(screen.getByText('Total')).toBeInTheDocument()
    })

    it('renders correct counts', () => {
      mockHook({
        data: { data: mockApprovals, total: 3, page: 1, per_page: 20, status_counts: COUNTS },
      })
      render(<ApprovalsPage />)

      // Counts appear as CardTitle values - "1" for pending, "1" for approved, etc.
      // Use getAllByText since counts appear in both cards and tabs
      expect(screen.getAllByText('1').length).toBeGreaterThanOrEqual(1)
      expect(screen.getAllByText('3').length).toBeGreaterThanOrEqual(1)
    })
  })

  // ============================================
  // TABS
  // ============================================

  describe('tabs', () => {
    it('renders status filter tabs with counts', () => {
      mockHook({
        data: { data: mockApprovals, total: 3, page: 1, per_page: 20, status_counts: COUNTS },
      })
      render(<ApprovalsPage />)

      expect(screen.getByRole('tab', { name: /^All\s*3$/i })).toBeInTheDocument()
      expect(screen.getByRole('tab', { name: /^Pending\s*1$/i })).toBeInTheDocument()
      expect(screen.getByRole('tab', { name: /^Approved\s*1$/i })).toBeInTheDocument()
      expect(screen.getByRole('tab', { name: /^Rejected\s*1$/i })).toBeInTheDocument()
      expect(screen.getByRole('tab', { name: /^Canceled\s*0$/i })).toBeInTheDocument()
    })
  })

  describe('server-side tabs', () => {
    it('asks the server for every status on the All tab', () => {
      mockHook({
        data: { data: mockApprovals, total: 3, page: 1, per_page: 20, status_counts: COUNTS },
      })
      render(<ApprovalsPage />)
      expect(useApprovals).toHaveBeenLastCalledWith(1, 20, undefined)
    })

    it('asks the server for the tab status and starts at page 1', () => {
      mockHook({
        data: { data: mockApprovals, total: 3, page: 1, per_page: 20, status_counts: COUNTS },
      })
      render(<ApprovalsPage />)
      fireEvent.mouseDown(screen.getByRole('tab', { name: /^Approved/i }))
      // Choosing a tab writes the status to the URL (and page 1)...
      expect(listState.setFilter).toHaveBeenCalledWith('status', 'approved')
    })

    it('reads the tab from the URL and asks the server for that status', () => {
      listState.status = 'rejected'
      mockHook({
        data: { data: mockApprovals, total: 3, page: 1, per_page: 20, status_counts: COUNTS },
      })
      render(<ApprovalsPage />)
      expect(useApprovals).toHaveBeenLastCalledWith(1, 20, 'rejected')
      listState.status = ''
    })

    it('takes tab counts from the server, not from the rows of the page', () => {
      mockHook({
        data: {
          data: mockApprovals.slice(0, 1),
          total: 120,
          page: 1,
          per_page: 20,
          status_counts: { pending: 120, approved: 40, rejected: 7, canceled: 2, expired: 1 },
        },
      })
      render(<ApprovalsPage />)
      expect(screen.getByRole('tab', { name: /^All\s*170$/i })).toBeInTheDocument()
      expect(screen.getByRole('tab', { name: /^Approved\s*40$/i })).toBeInTheDocument()
      expect(screen.getByRole('tab', { name: /^Expired\s*1$/i })).toBeInTheDocument()
    })
  })

  // ============================================
  // TABLE RENDERING
  // ============================================

  describe('table rendering', () => {
    it('renders DataTable with all approval data', () => {
      mockHook({
        data: { data: mockApprovals, total: 3, page: 1, per_page: 20, status_counts: COUNTS },
      })
      render(<ApprovalsPage />)

      expect(screen.getByTestId('data-table')).toBeInTheDocument()
      const rows = screen.getAllByTestId('table-row')
      expect(rows).toHaveLength(3)
    })

    it('names the requester: you, a member, a former member or the AI actor', () => {
      const rowsData = [
        mockApprovals[0],
        { ...mockApprovals[1], requested_by_name: 'Lan Requester' },
        { ...mockApprovals[2], requested_by: 'user-9' },
        {
          ...mockApprovals[2],
          id: 'approval-4',
          requested_by: '',
          requested_by_actor: 'ai_triage',
        },
      ]
      mockHook({
        data: { data: rowsData, total: 4, page: 1, per_page: 20, status_counts: COUNTS },
      })
      render(<ApprovalsPage />)
      const col = (
        captured.columns as { id?: string; cell?: (c: unknown) => React.ReactNode }[]
      ).find((c) => c.id === 'requester')
      expect(col?.cell).toBeDefined()
      const { container } = render(
        <div>
          {rowsData.map((r) => (
            <div key={r.id}>{col?.cell?.({ row: { original: r } })}</div>
          ))}
        </div>
      )
      expect(container.textContent).toContain('You')
      expect(container.textContent).toContain('Lan Requester')
      expect(container.textContent).toContain('Former member')
      expect(container.textContent).toContain('AI triage')
    })
  })

  // ============================================
  // REFRESH
  // ============================================

  describe('refresh', () => {
    it('calls mutate when refresh button is clicked', () => {
      mockHook({ data: { data: [], total: 0, page: 1, per_page: 20, status_counts: {} } })
      render(<ApprovalsPage />)
      fireEvent.click(screen.getByText('Refresh'))
      expect(mockMutate).toHaveBeenCalled()
    })
  })
})

// ============================================
// APPROVAL POLICY: TIER, PROGRESS, APPROVE RESPONSES
// ============================================

describe('ApprovalsPage approval policy', () => {
  type Col = { id?: string; cell?: (c: unknown) => React.ReactNode }
  const dualRow = {
    ...mockApprovals[0],
    id: 'approval-9',
    requested_status: 'accepted',
    requested_by: 'user-2',
    tier: 'dual' as const,
    risk_class: 'critical' as const,
    approvals_required: 2,
    approvals_collected: 1,
  }

  beforeEach(() => {
    vi.clearAllMocks()
    mockHook({
      data: { data: [dualRow], total: 1, page: 1, per_page: 20, status_counts: COUNTS },
    })
  })

  function cell(id: string, row: unknown) {
    const col = (captured.columns as Col[]).find((c) => c.id === id)
    expect(col?.cell).toBeDefined()
    return render(<div>{col?.cell?.({ row: { original: row } })}</div>)
  }

  async function approveFromMenu() {
    const user = userEvent.setup()
    render(<ApprovalsPage />)
    const { container } = cell('actions', dualRow)
    await user.click(within(container).getByRole('button'))
    await user.click(await screen.findByRole('menuitem', { name: /approve/i }))
    const dialog = await screen.findByRole('alertdialog')
    await user.click(within(dialog).getByRole('button', { name: 'Approve' }))
  }

  it('shows the tier and the sign-off progress of a pending request', () => {
    render(<ApprovalsPage />)
    const { container } = cell('tier', dualRow)
    expect(container.textContent).toContain('Two approvers')
    expect(container.textContent).toContain('1 of 2 approvals')
  })

  it('says how many approvals are still needed after a recorded sign-off', async () => {
    mockTriggerApprove.mockResolvedValue({
      ...dualRow,
      status: 'pending',
      approvals_required: 3,
      approvals_collected: 2,
    })
    await approveFromMenu()
    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith('Your approval is recorded', {
        description: '1 more approval(s) needed before the status changes.',
      })
    )
  })

  it('localizes a refusal by the approval policy', async () => {
    mockTriggerApprove.mockRejectedValue({
      statusCode: 403,
      code: 'APPROVER_NOT_ELIGIBLE',
      details: { reason: 'asset_owner' },
    })
    await approveFromMenu()
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "You own this finding's asset, so you cannot approve hiding its risk."
      )
    )
  })

  it('asks for re-authentication when the step-up prompt was dismissed', async () => {
    mockTriggerApprove.mockRejectedValue({ statusCode: 403, code: 'STEP_UP_REQUIRED' })
    await approveFromMenu()
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith('Confirm your identity to approve this request.')
    )
  })
})

// ============================================
// GROUP EXCEPTIONS
// ============================================

describe('ApprovalsPage group exceptions', () => {
  type Col = { id?: string; cell?: (c: unknown) => React.ReactNode }
  const memberRow = {
    ...mockApprovals[0],
    id: 'approval-m',
    batch_id: 'batch-1',
    status: 'pending' as const,
  }

  beforeEach(() => {
    vi.clearAllMocks()
    listState.view = ''
    batchState.pendingTotal = 2
    mockHook({
      data: {
        data: [memberRow] as unknown as typeof mockApprovals,
        total: 1,
        page: 1,
        per_page: 20,
        status_counts: COUNTS,
      },
    })
  })

  function cell(id: string, row: unknown) {
    const col = (captured.columns as Col[]).find((c) => c.id === id)
    expect(col?.cell).toBeDefined()
    return render(<div>{col?.cell?.({ row: { original: row } })}</div>)
  }

  it('a member of a group exception offers no individual decision, only a link to its group', () => {
    render(<ApprovalsPage />)
    const { container } = cell('actions', memberRow)
    expect(within(container).queryByRole('button')).not.toBeInTheDocument()
    const link = within(container).getByRole('link', { name: /Part of a group exception/ })
    expect(link).toHaveAttribute('href', '/findings/approvals?view=groups&batch=batch-1')
  })

  it('a request outside any group keeps its actions menu', () => {
    render(<ApprovalsPage />)
    const { container } = cell('actions', { ...memberRow, batch_id: undefined })
    expect(within(container).getByRole('button')).toBeInTheDocument()
    expect(within(container).queryByRole('link')).not.toBeInTheDocument()
  })

  it('counts pending group exceptions on the view switch and switches through the URL', () => {
    render(<ApprovalsPage />)
    const tab = screen.getByRole('tab', { name: /Group exceptions/ })
    expect(tab).toHaveTextContent('2')
    fireEvent.mouseDown(tab)
    expect(listState.setFilter).toHaveBeenCalledWith('view', 'groups')
  })

  it('the groups view lists group exceptions with their task, tier and member count', () => {
    listState.view = 'groups'
    render(<ApprovalsPage />)
    const taskCol = (captured.columns as Col[]).find((c) => c.id === 'task')
    expect(taskCol).toBeDefined()
    const row = {
      id: 'batch-1',
      source_id: 'task-1',
      source_title: 'Patch OpenSSL on edge hosts',
      status: 'pending',
      tier: 'security',
      approvals_required: 1,
      approvals_collected: 0,
      member_count: 3,
    }
    const { container } = cell('task', row)
    expect(within(container).getByRole('link')).toHaveAttribute('href', '/remediation/tasks/task-1')
    expect(cell('tier', row).container.textContent).toContain('0 of 1 approvals')
    expect(cell('members', row).container.textContent).toBe('3')
  })
})
