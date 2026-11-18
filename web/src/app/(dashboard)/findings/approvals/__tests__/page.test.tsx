/**
 * Approvals Page Tests
 *
 * Tests for the redesigned approval requests page:
 * - Loading state shows skeleton
 * - Error state shows full-page error with retry
 * - Empty state shows message
 * - One tab row (the kind of request), counting only pending requests
 * - The status lens in the list toolbar, Pending by default, URL-synced
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
const captured = vi.hoisted(() => ({
  columns: [] as unknown[],
  mobileRow: undefined as undefined | ((row: unknown) => React.ReactNode),
}))

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
  // The finding an approve/reject dialog is about.
  useFindingApi: vi.fn(() => ({
    data: {
      id: 'finding-abc123def456',
      title: 'SQL injection in orders search',
      severity: 'high',
      cve_id: 'CVE-2026-0420',
      asset: { id: 'asset-1', name: 'orders-api' },
    },
    isLoading: false,
  })),
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

// What the signed-in user may do; a test removes a permission to check a gate.
const permState = vi.hoisted(() => ({ denied: new Set<string>() }))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => children,
  Permission: {
    FindingsApprove: 'findings:approve',
    FindingsWrite: 'findings:write',
    FindingsRead: 'findings:read',
  },
  usePermissions: () => ({ can: (p: string) => !permState.denied.has(p) }),
}))

// The row menu as plain buttons: what it offers is the page's decision; how a
// menu opens is the kit's (tested there).
vi.mock('@/components/ui/action-menu', () => ({
  ActionMenu: ({
    items,
    label,
  }: {
    items: { id: string; label: string; onSelect?: () => void }[]
    label: string
  }) => (
    <div role="group" aria-label={label}>
      {items.map((item) => (
        <button key={item.id} type="button" data-menu-item={item.id} onClick={item.onSelect}>
          {item.label}
        </button>
      ))}
    </div>
  ),
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
    emptyState,
    isLoading,
    error,
    onRetry,
    errorTitle,
    mobileRow,
    toolbarStart,
    toolbarEnd,
  }: {
    data: unknown[]
    toolbarStart?: React.ReactNode
    toolbarEnd?: React.ReactNode
    emptyMessage?: string
    emptyDescription?: string
    emptyState?: React.ReactNode
    isLoading?: boolean
    error?: unknown
    onRetry?: () => void
    errorTitle?: string
    mobileRow?: (row: unknown) => React.ReactNode
    columns: unknown[]
    searchPlaceholder?: string
    searchKey?: string
    showColumnToggle?: boolean
    pageSize?: number
  }) => {
    captured.columns = columns
    captured.mobileRow = mobileRow
    return (
      <div data-testid="data-table">
        <div data-testid="toolbar">
          {toolbarStart}
          {toolbarEnd}
        </div>
        {isLoading ? (
          <div data-slot="skeleton" />
        ) : error && data.length === 0 ? (
          <div role="alert">
            Failed to load {errorTitle}
            <button type="button" onClick={onRetry}>
              Retry
            </button>
          </div>
        ) : data.length === 0 ? (
          <div data-testid="table-empty">
            {emptyState ?? (
              <>
                <p>{emptyMessage}</p>
                <p>{emptyDescription}</p>
              </>
            )}
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
import { useApprovals, remindApprovers } from '@/features/findings/api/use-findings-api'
import { ApiClientError } from '@/lib/api/error-handler'

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

    it('says the count once: under Pending the tab carries it, the title row does not', () => {
      mockHook({
        data: { data: mockApprovals, total: 3, page: 1, per_page: 20, status_counts: COUNTS },
      })
      const { container } = render(<ApprovalsPage />)
      // The view is named for assistive technology; the selected tab shows the number.
      expect(screen.getByRole('heading', { name: 'Pending requests' })).toHaveClass('sr-only')
      expect(container.querySelector('[data-slot="list-count"]')).toBeNull()
      expect(screen.getByRole('tab', { name: /Requests/ })).toHaveTextContent(
        String(COUNTS.pending)
      )
      // No second count in the page header.
      expect(screen.queryByText(/waiting for a decision/)).not.toBeInTheDocument()
    })

    it('says the count of another lens in the title row (no tab shows that number)', () => {
      listState.status = 'all'
      mockHook({
        data: { data: mockApprovals, total: 3, page: 1, per_page: 20, status_counts: COUNTS },
      })
      const { container } = render(<ApprovalsPage />)
      const counts = container.querySelectorAll('[data-slot="list-count"]')
      expect(counts).toHaveLength(1)
      expect(counts[0]).toHaveTextContent('3 requests')
      listState.status = ''
    })

    it('names the view after the status lens', () => {
      listState.status = 'rejected'
      mockHook({ data: { data: [], total: 0, page: 1, per_page: 20, status_counts: COUNTS } })
      render(<ApprovalsPage />)
      expect(screen.getByRole('heading', { name: 'Rejected requests' })).toBeInTheDocument()
      listState.status = ''
    })

    it('keeps the count slot empty while the first read is on its way', () => {
      listState.status = 'all'
      mockHook({ isLoading: true })
      const { container } = render(<ApprovalsPage />)
      expect(container.querySelector('[data-slot="list-count"]')).toBeEmptyDOMElement()
      listState.status = ''
    })

    it('has no title-case back link: the sidebar already leads to Findings', () => {
      mockHook({ data: { data: [], total: 0, page: 1, per_page: 20, status_counts: {} } })
      render(<ApprovalsPage />)
      expect(screen.queryByText('Back to Findings')).not.toBeInTheDocument()
    })

    it('renders refresh button', () => {
      mockHook({ data: { data: [], total: 0, page: 1, per_page: 20, status_counts: {} } })
      render(<ApprovalsPage />)
      expect(screen.getByRole('button', { name: 'Refresh' })).toBeInTheDocument()
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
    it('shows the error inside the list, keeping the header and the tabs', () => {
      mockHook({ error: new Error('Network error') })
      render(<ApprovalsPage />)
      expect(screen.getByRole('heading', { name: 'Approval requests' })).toBeInTheDocument()
      expect(screen.getByRole('tab', { name: /Group exceptions/ })).toBeInTheDocument()
      expect(screen.getByRole('alert')).toHaveTextContent(/approval requests/)
      // The toolbar stays: the lens can still be changed.
      expect(screen.getByTestId('toolbar')).not.toBeEmptyDOMElement()
    })

    it('a refused read says no access, with no Retry', () => {
      mockHook({ error: Object.assign(new Error('forbidden'), { statusCode: 403 }) })
      render(<ApprovalsPage />)
      expect(screen.getByText(/do not have access/i)).toBeInTheDocument()
      expect(screen.queryByRole('button', { name: /retry/i })).not.toBeInTheDocument()
      expect(screen.queryByTestId('data-table')).not.toBeInTheDocument()
      expect(screen.getByRole('tab', { name: /Group exceptions/ })).toBeInTheDocument()
    })

    it('calls mutate when retry is clicked', () => {
      mockHook({ error: new Error('Network error') })
      render(<ApprovalsPage />)
      fireEvent.click(screen.getByRole('button', { name: /retry/i }))
      expect(mockMutate).toHaveBeenCalled()
    })
  })

  // ============================================
  // EMPTY STATE
  // ============================================

  describe('empty state', () => {
    it('first run: the queue never held a request, and no way out is offered', () => {
      mockHook({ data: { data: [], total: 0, page: 1, per_page: 20, status_counts: {} } })
      render(<ApprovalsPage />)
      const empty = screen.getByTestId('table-empty')
      expect(empty.querySelector('[data-kind="first-run"]')).toBeTruthy()
      expect(empty).toHaveTextContent('No approval requests')
      expect(within(empty).queryByRole('button')).not.toBeInTheDocument()
    })

    it('nothing waiting: decided requests exist, and Show all requests opens them', async () => {
      mockHook({
        data: {
          data: [],
          total: 0,
          page: 1,
          per_page: 20,
          status_counts: { ...COUNTS, pending: 0 },
        },
      })
      render(<ApprovalsPage />)
      const empty = screen.getByTestId('table-empty')
      expect(empty.querySelector('[data-kind="nothing-waiting"]')).toBeTruthy()
      expect(empty).toHaveTextContent('Nothing is waiting for a decision')
      fireEvent.click(within(empty).getByRole('button', { name: 'Show all requests' }))
      expect(listState.setFilter).toHaveBeenCalledWith('status', 'all')
    })

    it('no match: the lens left no row', () => {
      listState.status = 'rejected'
      mockHook({
        data: {
          data: [],
          total: 0,
          page: 1,
          per_page: 20,
          status_counts: { ...COUNTS, rejected: 0 },
        },
      })
      render(<ApprovalsPage />)
      const empty = screen.getByTestId('table-empty')
      expect(empty.querySelector('[data-kind="no-match"]')).toBeTruthy()
      expect(empty).toHaveTextContent('No requests with the status Rejected.')
      listState.status = ''
    })
  })

  // ============================================
  // ONE TAB ROW + STATUS LENS
  // ============================================

  describe('one tab row', () => {
    it('renders a single tab row: the kind of request, not the status', () => {
      mockHook({
        data: { data: mockApprovals, total: 3, page: 1, per_page: 20, status_counts: COUNTS },
      })
      render(<ApprovalsPage />)
      expect(screen.getAllByRole('tablist')).toHaveLength(1)
      expect(screen.getAllByRole('tab').map((el) => el.textContent)).toEqual([
        'Finding requests1',
        'Group exceptions',
      ])
    })

    it('counts only pending requests, from the server, and hides a zero', () => {
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
      expect(screen.getByRole('tab', { name: /^Finding requests\s*120$/ })).toBeInTheDocument()
      expect(screen.getByRole('tab', { name: /^Group exceptions$/ })).toBeInTheDocument()
      // The title row counts the list on screen, once.
      expect(document.querySelector('[data-slot="list-count"]')).toHaveTextContent('120 requests')
    })
  })

  describe('status filter', () => {
    beforeEach(() => {
      mockHook({
        data: { data: mockApprovals, total: 3, page: 1, per_page: 20, status_counts: COUNTS },
      })
    })

    it('sits in the list toolbar as a Status filter token, not a row of tabs', () => {
      render(<ApprovalsPage />)
      const toolbar = screen.getByTestId('toolbar')
      expect(within(toolbar).queryByRole('radiogroup')).not.toBeInTheDocument()
      expect(within(toolbar).getByRole('button', { name: 'Status: Pending' })).toBeInTheDocument()
    })

    it('lists every status with its count in the token menu', async () => {
      render(<ApprovalsPage />)
      await userEvent.click(screen.getByRole('button', { name: 'Status: Pending' }))
      const items = await screen.findAllByRole('menuitemradio')
      expect(items.map((el) => el.textContent?.replace(/[\d,]+$/, ''))).toEqual([
        'All',
        'Pending',
        'Approved',
        'Rejected',
      ])
    })

    it('opens on Pending and asks the server for pending requests', () => {
      render(<ApprovalsPage />)
      expect(useApprovals).toHaveBeenLastCalledWith(1, 20, 'pending')
    })

    it('writes the status to the URL; Pending is the default and leaves it out', async () => {
      render(<ApprovalsPage />)
      // Clearing the token shows every status.
      fireEvent.click(screen.getByRole('button', { name: 'Clear Status' }))
      expect(listState.setFilter).toHaveBeenCalledWith('status', 'all')
      await userEvent.click(screen.getByRole('button', { name: 'Status: Pending' }))
      await userEvent.click(await screen.findByRole('menuitemradio', { name: /^Rejected/ }))
      expect(listState.setFilter).toHaveBeenCalledWith('status', 'rejected')
    })

    it('asks the server for every status under All', () => {
      listState.status = 'all'
      render(<ApprovalsPage />)
      expect(useApprovals).toHaveBeenLastCalledWith(1, 20, undefined)
      listState.status = ''
    })

    it('reads the lens from the URL and asks the server for that status', () => {
      listState.status = 'rejected'
      render(<ApprovalsPage />)
      expect(useApprovals).toHaveBeenLastCalledWith(1, 20, 'rejected')
      expect(screen.getByRole('button', { name: 'Status: Rejected' })).toBeInTheDocument()
      listState.status = ''
    })

    it('falls back to Pending for a status that is not a lens', () => {
      listState.status = 'canceled'
      render(<ApprovalsPage />)
      expect(useApprovals).toHaveBeenLastCalledWith(1, 20, 'pending')
      listState.status = ''
    })

    it('explains an empty Pending list', () => {
      mockHook({
        data: {
          data: [],
          total: 0,
          page: 1,
          per_page: 20,
          status_counts: { ...COUNTS, pending: 0 },
        },
      })
      render(<ApprovalsPage />)
      expect(
        screen.getByText(/To see decided requests, change the Status filter/)
      ).toBeInTheDocument()
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
      fireEvent.click(screen.getByRole('button', { name: 'Refresh' }))
      expect(mockMutate).toHaveBeenCalled()
      // The spinning button is the feedback; no toast for a visible change.
      expect(toast.success).not.toHaveBeenCalled()
    })

    it('never offers a header sort on one page of a server-paginated list', () => {
      mockHook({
        data: { data: mockApprovals, total: 3, page: 1, per_page: 20, status_counts: COUNTS },
      })
      render(<ApprovalsPage />)
      const sortable = (captured.columns as { enableSorting?: boolean }[]).filter(
        (c) => c.enableSorting !== false
      )
      expect(sortable).toHaveLength(0)
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
    await user.click(within(container).getByRole('button', { name: /approve/i }))
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

  it('a request outside any group offers its decision on the row', () => {
    render(<ApprovalsPage />)
    const { container } = cell('actions', {
      ...memberRow,
      batch_id: undefined,
      requested_by: 'user-2',
    })
    expect(within(container).getByRole('button', { name: /approve/i })).toBeInTheDocument()
    expect(within(container).getByRole('button', { name: /reject/i })).toBeInTheDocument()
    expect(within(container).queryByRole('link')).not.toBeInTheDocument()
  })

  it('the active tab points at a panel that exists', () => {
    render(<ApprovalsPage />)
    const tab = screen.getByRole('tab', { name: /Finding requests/ })
    const panel = tab.getAttribute('aria-controls')
    expect(panel && document.getElementById(panel)).toBeTruthy()
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

// ============================================
// DECIDING: THE ROW, THE DIALOGS, A FAILED REJECT
// ============================================

describe('ApprovalsPage deciding', () => {
  type Col = { id?: string; cell?: (c: unknown) => React.ReactNode }
  const otherRow = {
    ...mockApprovals[0],
    id: 'approval-o',
    requested_by: 'user-2',
    finding_title: 'SQL injection in orders search',
    justification: 'Only reachable from the test harness.\nSee ticket OPS-1.',
  }

  beforeEach(() => {
    vi.clearAllMocks()
    listState.view = ''
    mockHook({
      data: {
        data: [otherRow] as unknown as typeof mockApprovals,
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

  it('your own request shows no decision buttons, only that it is yours', () => {
    render(<ApprovalsPage />)
    const { container } = cell('actions', { ...otherRow, requested_by: 'user-1' })
    expect(within(container).queryByRole('button', { name: /^approve/i })).toBeNull()
    expect(within(container).queryByRole('button', { name: /^reject/i })).toBeNull()
    expect(container).toHaveTextContent('Your request')
    // The reason is there for assistive technology and on hover or focus.
    expect(container).toHaveTextContent('Another approver must decide your own request.')
  })

  it('the actions menu is named after the finding', () => {
    render(<ApprovalsPage />)
    const { container } = cell('actions', { ...otherRow, requested_by: 'user-1' })
    expect(
      within(container).getByRole('group', {
        name: 'Actions for SQL injection in orders search',
      })
    ).toBeInTheDocument()
  })

  it('the reject dialog shows the finding and the whole justification', async () => {
    const user = userEvent.setup()
    render(<ApprovalsPage />)
    const { container } = cell('actions', otherRow)
    await user.click(within(container).getByRole('button', { name: /reject/i }))
    const dialog = await screen.findByRole('dialog')
    const summary = within(dialog).getByTestId('approval-finding-summary')
    expect(summary).toHaveTextContent('SQL injection in orders search')
    expect(summary).toHaveTextContent('orders-api')
    expect(summary).toHaveTextContent('CVE-2026-0420')
    const just = within(dialog).getByTestId('approval-justification')
    expect(just).toHaveAttribute('dir', 'auto')
    expect(just.textContent).toContain('See ticket OPS-1.')
    expect(within(dialog).getByRole('link', { name: /open finding/i })).toHaveAttribute(
      'href',
      '/findings/finding-abc123def456'
    )
  })

  it('a failed reject keeps the dialog open with the typed reason and says why', async () => {
    mockTriggerReject.mockRejectedValue(new Error('boom'))
    const user = userEvent.setup()
    render(<ApprovalsPage />)
    const { container } = cell('actions', otherRow)
    await user.click(within(container).getByRole('button', { name: /reject/i }))
    const dialog = await screen.findByRole('dialog')
    const box = within(dialog).getByRole('textbox')
    fireEvent.change(box, { target: { value: 'Not reachable is not proven' } })
    await user.click(within(dialog).getByRole('button', { name: 'Reject' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Failed to reject request')
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(within(dialog).getByRole('textbox')).toHaveValue('Not reachable is not proven')
    expect(toast.error).not.toHaveBeenCalled()
  })

  it('a successful reject closes the dialog', async () => {
    mockTriggerReject.mockResolvedValue({})
    const user = userEvent.setup()
    render(<ApprovalsPage />)
    const { container } = cell('actions', otherRow)
    await user.click(within(container).getByRole('button', { name: /reject/i }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByRole('textbox'), {
      target: { value: 'Reachable from the internet' },
    })
    await user.click(within(dialog).getByRole('button', { name: 'Reject' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(mockTriggerReject).toHaveBeenCalledWith({ reason: 'Reachable from the internet' })
  })
})

// ============================================
// THE QUEUE'S GATES: PERMISSIONS, FOUR EYES, CONFIRMS, LIMITS
// ============================================

describe('ApprovalsPage gates', () => {
  type Col = { id?: string; accessorKey?: string; cell?: (c: unknown) => React.ReactNode }
  const otherRow = {
    ...mockApprovals[0],
    id: 'approval-o',
    requested_by: 'user-2',
    finding_title: 'SQL injection in orders search',
  }
  const ownRow = { ...otherRow, id: 'approval-mine', requested_by: 'user-1' }

  function page(selfApproval = false, rows: unknown[] = [otherRow]) {
    mockHook({
      data: {
        data: rows as unknown as typeof mockApprovals,
        total: rows.length,
        page: 1,
        per_page: 20,
        status_counts: COUNTS,
        ...(selfApproval ? { self_approval_available: true } : {}),
      } as never,
    })
    return render(<ApprovalsPage />)
  }

  function cell(id: string, row: unknown) {
    const col = (captured.columns as Col[]).find((c) => c.id === id || c.accessorKey === id)
    expect(col?.cell).toBeDefined()
    return render(<div>{col?.cell?.({ row: { original: row } })}</div>)
  }

  beforeEach(() => {
    vi.clearAllMocks()
    permState.denied.clear()
    listState.view = ''
    listState.status = ''
  })

  it('without findings:approve a request of someone else offers no decision at all', () => {
    permState.denied.add('findings:approve')
    page()
    const { container } = cell('actions', otherRow)
    expect(container.firstChild).toBeEmptyDOMElement()
  })

  it('four eyes: your own request has no Approve or Reject even with findings:approve', () => {
    page()
    const { container } = cell('actions', ownRow)
    expect(within(container).queryByRole('button', { name: /^approve /i })).toBeNull()
    expect(within(container).queryByRole('button', { name: /^reject /i })).toBeNull()
    expect(container.querySelector('[data-slot="queue-own-request"]')).toHaveTextContent(
      'Your request'
    )
  })

  it('four eyes: without findings:approve "Your request" is not shown either (as before)', () => {
    permState.denied.add('findings:approve')
    page()
    const { container } = cell('actions', ownRow)
    expect(container.querySelector('[data-slot="queue-own-request"]')).toBeNull()
    // Remind and Cancel stay: they need findings:write and the request being yours.
    expect(within(container).getByRole('button', { name: 'Remind approvers' })).toBeInTheDocument()
  })

  it('Remind and Cancel are offered only to the requester', () => {
    page()
    expect(within(cell('actions', otherRow).container).queryByRole('group')).toBeNull()
    const own = cell('actions', ownRow).container
    expect(within(own).getByRole('button', { name: 'Remind approvers' })).toBeInTheDocument()
    expect(within(own).getByRole('button', { name: 'Cancel request' })).toBeInTheDocument()
  })

  it('Remind and Cancel need findings:write', () => {
    permState.denied.add('findings:write')
    page()
    const { container } = cell('actions', ownRow)
    expect(within(container).queryByRole('group')).toBeNull()
  })

  it('self-approval is offered only when the API says the organization has one member', () => {
    page(false)
    expect(
      within(cell('actions', ownRow).container).queryByRole('button', { name: /Approve myself/ })
    ).toBeNull()
    page(true)
    expect(
      within(cell('actions', ownRow).container).getByRole('button', { name: /Approve myself/ })
    ).toBeInTheDocument()
  })

  it('self-approval needs findings:approve', () => {
    permState.denied.add('findings:approve')
    page(true)
    expect(
      within(cell('actions', ownRow).container).queryByRole('button', { name: /Approve myself/ })
    ).toBeNull()
  })

  it('a decided request offers nothing', () => {
    page()
    const { container } = cell('actions', { ...otherRow, status: 'approved' })
    expect(container.firstChild).toBeEmptyDOMElement()
  })

  it('Remind asks first, then sends, and says the result to screen readers', async () => {
    vi.mocked(remindApprovers).mockResolvedValue({ reminded: 2 })
    const user = userEvent.setup()
    const { container: pageEl } = page()
    const { container } = cell('actions', ownRow)
    await user.click(within(container).getByRole('button', { name: 'Remind approvers' }))
    expect(remindApprovers).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Approvers can be reminded once an hour.')
    await user.click(within(dialog).getByRole('button', { name: 'Send reminder' }))
    await waitFor(() => expect(remindApprovers).toHaveBeenCalledWith('approval-mine'))
    await waitFor(() =>
      expect(pageEl.querySelector('[data-slot="queue-announcer"]')).toHaveTextContent(
        'Reminded 2 approver(s)'
      )
    )
    expect(toast.success).toHaveBeenCalledWith('Reminded 2 approver(s)')
  })

  it('a second reminder within the hour is refused with the reason', async () => {
    const tooSoon = Object.assign(new ApiClientError('conflict'), { statusCode: 409 })
    vi.mocked(remindApprovers).mockRejectedValue(tooSoon)
    const user = userEvent.setup()
    const { container: pageEl } = page()
    const { container } = cell('actions', ownRow)
    await user.click(within(container).getByRole('button', { name: 'Remind approvers' }))
    const dialog = await screen.findByRole('alertdialog')
    await user.click(within(dialog).getByRole('button', { name: 'Send reminder' }))
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        'The approvers were already reminded in the last hour.'
      )
    )
    expect(pageEl.querySelector('[data-slot="queue-announcer"]')).toHaveTextContent(
      'The approvers were already reminded in the last hour.'
    )
  })

  it('Cancel request asks with a destructive confirm before anything is sent', async () => {
    mockTriggerCancel.mockResolvedValue({})
    const user = userEvent.setup()
    page()
    const { container } = cell('actions', ownRow)
    await user.click(within(container).getByRole('button', { name: 'Cancel request' }))
    expect(mockTriggerCancel).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Cancel this approval request?')
    expect(within(dialog).getByRole('button', { name: 'Keep request' })).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Cancel request' }))
    await waitFor(() => expect(mockTriggerCancel).toHaveBeenCalled())
    expect(toast.success).toHaveBeenCalledWith('Approval request canceled')
  })

  it('a reject needs a reason: the button is inert until one is typed', async () => {
    const user = userEvent.setup()
    page()
    const { container } = cell('actions', otherRow)
    await user.click(within(container).getByRole('button', { name: /reject/i }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('button', { name: 'Reject' })).toBeDisabled()
    fireEvent.change(within(dialog).getByRole('textbox'), { target: { value: '   ' } })
    expect(within(dialog).getByRole('button', { name: 'Reject' })).toBeDisabled()
    expect(mockTriggerReject).not.toHaveBeenCalled()
  })

  it('a decision is said to screen readers', async () => {
    mockTriggerReject.mockResolvedValue({})
    const user = userEvent.setup()
    const { container: pageEl } = page()
    const { container } = cell('actions', otherRow)
    await user.click(within(container).getByRole('button', { name: /reject/i }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByRole('textbox'), { target: { value: 'Reachable' } })
    await user.click(within(dialog).getByRole('button', { name: 'Reject' }))
    await waitFor(() =>
      expect(pageEl.querySelector('[data-slot="queue-announcer"]')).toHaveTextContent(
        'Approval request rejected'
      )
    )
  })

  it('an AI-proposed request keeps its AI mark in the row and on the phone card', () => {
    const aiRow = { ...otherRow, requested_by: '', requested_by_actor: 'ai_triage' }
    page(false, [aiRow])
    expect(
      cell('justification', aiRow).container.querySelector('[data-testid="ai-badge"]')
    ).toBeTruthy()
    const card = render(<div>{captured.mobileRow?.(aiRow)}</div>).container
    expect(card.querySelector('[data-testid="ai-badge"]')).toBeTruthy()
  })

  it('decide-by is a date, and says Overdue once it has passed', () => {
    page()
    const late = cell('decide_by', { ...otherRow, decide_by: '2020-01-05T00:00:00Z' }).container
    expect(late.querySelector('[data-state="overdue"]')).toHaveTextContent(/^Overdue, /)
    const due = cell('decide_by', { ...otherRow, decide_by: '2999-01-05T00:00:00Z' }).container
    expect(due.querySelector('[data-state="due"]')).toHaveTextContent(/2999/)
    // A decided request has nothing to decide by.
    const done = cell('decide_by', {
      ...otherRow,
      status: 'approved',
      decide_by: '2020-01-05T00:00:00Z',
    })
    expect(done.container.querySelector('[data-slot="queue-decide-by"]')).toBeNull()
  })

  it('the Status column shows on every lens but Pending, where each row would repeat it', () => {
    page()
    expect((captured.columns as Col[]).some((c) => c.accessorKey === 'status')).toBe(false)
    listState.status = 'all'
    page()
    expect((captured.columns as Col[]).some((c) => c.accessorKey === 'status')).toBe(true)
  })

  it('the finding leads the row and the decision ends it', () => {
    page()
    const cols = captured.columns as Col[]
    expect(cols[0].accessorKey).toBe('finding_id')
    expect(cols[cols.length - 1].id).toBe('actions')
  })

  it('the phone card carries the same decision controls and the four-eyes reason in words', () => {
    page()
    const other = render(<div>{captured.mobileRow?.(otherRow)}</div>).container
    expect(within(other).getByRole('button', { name: /^approve /i })).toBeInTheDocument()
    expect(within(other).getByRole('button', { name: /^reject /i })).toBeInTheDocument()
    const own = render(<div>{captured.mobileRow?.(ownRow)}</div>).container
    expect(within(own).queryByRole('button', { name: /^approve /i })).toBeNull()
    expect(own.querySelector('[data-slot="queue-own-request"]')).toHaveTextContent(
      'Your request Another approver must decide your own request.'
    )
  })
})
