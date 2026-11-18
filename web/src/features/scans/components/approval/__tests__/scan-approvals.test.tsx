/**
 * Scan approval UI (RFC-073): the New Scan notice says who must approve and
 * asks for the evidence the rules need; the inbox offers Approve only when
 * the API says the viewer may, and self-approval only with a reason and a
 * code; the list badge shows a waiting scan.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ScanApprovalRequest } from '@/lib/api/scan-approval-hooks'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const api = vi.hoisted(() => ({
  list: { data: [] as ScanApprovalRequest[], total: 0 } as
    { data: ScanApprovalRequest[]; total: number } | undefined,
  error: undefined as unknown,
  read: vi.fn(),
  approve: vi.fn(),
  reject: vi.fn(),
  selfApprove: vi.fn(),
  remind: vi.fn(),
  cancel: vi.fn(),
  mutate: vi.fn(),
  refresh: vi.fn(),
}))
vi.mock('@/lib/api/scan-approval-hooks', () => ({
  useScanApprovals: (...args: unknown[]) => {
    api.read(...args)
    return {
      data: api.list,
      error: api.error,
      isLoading: false,
      isValidating: false,
      mutate: api.mutate,
    }
  },
  refreshScanApprovals: api.refresh,
  approveScanRequest: api.approve,
  rejectScanRequest: api.reject,
  selfApproveScanRequest: api.selfApprove,
  remindScanApprovers: api.remind,
  cancelScanRequest: api.cancel,
}))
// The status lens and the page live in the URL through useListParams.
const listState = vi.hoisted(() => ({ status: '', setFilter: vi.fn() }))
vi.mock('@/hooks/use-list-params', () => ({
  useListParams: () => ({
    page: 2,
    perPage: 25,
    filters: { status: listState.status },
    pagination: { pageIndex: 1, pageSize: 25 },
    setPagination: vi.fn(),
    setFilter: listState.setFilter,
  }),
}))
// The page knows the signed-in person from the profile, not the auth store
// (the session token is not readable by the page).
vi.mock('@/hooks/use-display-user', () => ({ useDisplayUser: () => ({ id: 'me' }) }))
vi.mock('@/components/link', () => ({
  default: ({ href, children }: { href: string; children: React.ReactNode }) => (
    <a href={href}>{children}</a>
  ),
}))

const { ApprovalRequirement, missingEvidence, approversText } =
  await import('../approval-requirement')
const { ScanApprovalsInbox } = await import('../scan-approvals-inbox')
const { ScanApprovalBadge } = await import('../scan-approval-badge')

const t = (_k: string, fallback?: string, vars?: Record<string, string | number>) => {
  let s = fallback ?? _k
  for (const [k, v] of Object.entries(vars ?? {})) s = s.split(`{${k}}`).join(String(v))
  return s
}

function request(over: Partial<ScanApprovalRequest> = {}): ScanApprovalRequest {
  return {
    id: 'r1',
    scan_id: 's1',
    scan_name: 'Web pentest',
    status: 'pending',
    definition_digest: 'sha256:x',
    definition: { targets: ['app.example.com'], intensity: 'intrusive', scanner_name: 'zap' },
    changes: [{ field: 'targets', before: ['a'], after: ['a', 'b'] }],
    evaluation: {
      mode: 'on',
      required: true,
      approvals: 1,
      matched: [{ id: 'x', name: 'Intrusive scans', requirement: { approvals: 1 } }],
    },
    run_on_approval: false,
    requested_by: { id: 'other', name: 'Mai' },
    requested_at: new Date().toISOString(),
    expires_at: new Date().toISOString(),
    approvals: [],
    remaining: 1,
    emergency: false,
    can_approve: true,
    self_approval_available: false,
    eligible_approver_count: 1,
    ...over,
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  api.error = undefined
  listState.status = ''
})

describe('New Scan approval notice', () => {
  it('says who approves and asks for the evidence', () => {
    const ev = {
      mode: 'strict' as const,
      required: true,
      approvals: 2,
      approver_roles: ['admin'],
      require_justification: true,
      require_ticket: true,
      ticket_patterns: ['CHG-[0-9]+'],
      matched: [{ id: 'r', name: 'Production', requirement: { approvals: 2 } }],
    }
    render(
      <ApprovalRequirement
        evaluation={ev}
        justification=""
        ticket=""
        onJustification={vi.fn()}
        onTicket={vi.fn()}
      />
    )
    expect(
      screen.getByText(/Needs approval by 2 distinct approvers: an administrator/)
    ).toBeInTheDocument()
    expect(screen.getByText('Production')).toBeInTheDocument()
    expect(screen.getByLabelText('Justification')).toBeInTheDocument()
    expect(screen.getByLabelText('Change ticket')).toBeInTheDocument()
    expect(missingEvidence(t, ev, '', '')).toMatch(/justification/)
    expect(missingEvidence(t, ev, 'why', 'INC-1')).toMatch(/format/)
    expect(missingEvidence(t, ev, 'why', 'CHG-42')).toBe('')
  })

  it('shows nothing when no approval is needed', () => {
    const { container } = render(
      <ApprovalRequirement
        evaluation={{ mode: 'on', required: false }}
        justification=""
        ticket=""
        onJustification={vi.fn()}
        onTicket={vi.fn()}
      />
    )
    expect(container).toBeEmptyDOMElement()
    expect(approversText(t, { mode: 'on', required: true, approvals: 1 })).toBe(
      '1 approver with the scan approval permission'
    )
  })
})

describe('Approvals inbox', () => {
  it('approves with a note when the API allows the viewer, and says so', async () => {
    api.list = { data: [request()], total: 1 }
    api.approve.mockResolvedValue(request({ status: 'approved' }))
    const user = userEvent.setup()
    render(<ScanApprovalsInbox />)
    expect(screen.getAllByText('Web pentest').length).toBeGreaterThan(0)
    // What the scan will do opens on demand, from the row's More.
    await user.click(screen.getAllByRole('button', { name: 'Actions for Web pentest' })[0])
    await user.click(await screen.findByRole('menuitem', { name: 'Details' }))
    expect(await screen.findByText('Changed since the last approval')).toBeInTheDocument()
    await user.keyboard('{Escape}')
    await user.click(screen.getAllByRole('button', { name: 'Approve Web pentest' })[0])
    await user.type(await screen.findByLabelText('Note (optional)'), 'ok')
    await user.click(screen.getByRole('button', { name: 'Approve' }))
    await waitFor(() => expect(api.approve).toHaveBeenCalledWith('r1', 'ok'))
    await waitFor(() => expect(api.refresh).toHaveBeenCalled())
    expect(document.querySelector('[data-slot=queue-announcer]')).toHaveTextContent(
      'Approval recorded'
    )
  })

  // The API returns at most 100 requests a page; nothing past it may be dropped.
  it('reads the page in the URL and counts every request', () => {
    api.list = {
      data: Array.from({ length: 25 }, (_, i) => request({ id: `r${i}` })),
      total: 130,
    }
    render(<ScanApprovalsInbox />)
    expect(api.read).toHaveBeenCalledWith('pending', 2, 25)
    expect(screen.getByText('130')).toBeInTheDocument()
  })

  it('reads every request under All and one status under its lens', () => {
    api.list = { data: [request({ status: 'approved' })], total: 1 }
    listState.status = 'all'
    const { unmount } = render(<ScanApprovalsInbox />)
    expect(api.read).toHaveBeenLastCalledWith('', 2, 25)
    expect(document.querySelector('[data-slot=list-title-row]')).toHaveTextContent(
      'All scan requests'
    )
    unmount()
    listState.status = 'expired'
    render(<ScanApprovalsInbox />)
    expect(api.read).toHaveBeenLastCalledWith('expired', 2, 25)
  })

  it("names the intensity with the scans' translated label, never the raw value", () => {
    api.list = { data: [request()], total: 1 }
    render(<ScanApprovalsInbox />)
    expect(screen.getAllByText('Intrusive (full)').length).toBeGreaterThan(0)
    expect(screen.queryByText('intrusive')).toBeNull()
  })

  it('offers Show all when nothing waits', async () => {
    api.list = { data: [], total: 0 }
    render(<ScanApprovalsInbox />)
    expect(screen.getByText('No scan waits for approval')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Show all requests' }))
    expect(listState.setFilter).toHaveBeenCalledWith('status', 'all')
  })

  it('a refused read says no access, without Retry', () => {
    api.list = undefined
    api.error = Object.assign(new Error('forbidden'), { statusCode: 403 })
    render(<ScanApprovalsInbox />)
    expect(screen.queryByRole('button', { name: /Retry/ })).toBeNull()
    expect(screen.queryByRole('table')).toBeNull()
  })

  it('offers no decision when the API says the viewer may not approve', () => {
    api.list = { data: [request({ can_approve: false })], total: 1 }
    render(<ScanApprovalsInbox />)
    expect(screen.queryByRole('button', { name: /^Approve/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Reject/ })).not.toBeInTheDocument()
  })

  it('a requester reminds, and withdraws only after a confirm', async () => {
    api.list = {
      data: [request({ can_approve: false, requested_by: { id: 'me', name: 'Me' } })],
      total: 1,
    }
    api.remind.mockResolvedValue(request())
    api.cancel.mockResolvedValue(request({ status: 'canceled' }))
    const user = userEvent.setup()
    render(<ScanApprovalsInbox />)
    expect(screen.getAllByText('Your request').length).toBeGreaterThan(0)
    await user.click(screen.getAllByRole('button', { name: 'Actions for Web pentest' })[0])
    await user.click(await screen.findByRole('menuitem', { name: 'Remind' }))
    await waitFor(() => expect(api.remind).toHaveBeenCalledWith('r1'))
    await user.click(screen.getAllByRole('button', { name: 'Actions for Web pentest' })[0])
    await user.click(await screen.findByRole('menuitem', { name: 'Withdraw' }))
    expect(api.cancel).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Withdraw this request?')
    await user.click(screen.getByRole('button', { name: 'Withdraw' }))
    await waitFor(() => expect(api.cancel).toHaveBeenCalledWith('r1'))
  })

  it('self-approval needs a reason and an authenticator code', async () => {
    api.list = {
      data: [
        request({
          can_approve: false,
          self_approval_available: true,
          requested_by: { id: 'me', name: 'Me' },
        }),
      ],
      total: 1,
    }
    api.selfApprove.mockResolvedValue(request({ status: 'approved' }))
    const user = userEvent.setup()
    render(<ScanApprovalsInbox />)
    await user.click(screen.getAllByRole('button', { name: 'Actions for Web pentest' })[0])
    await user.click(await screen.findByRole('menuitem', { name: /Approve my own scan/ }))
    const confirm = screen.getAllByRole('button', { name: 'Approve' }).pop()!
    expect(confirm).toBeDisabled()
    await user.type(screen.getByLabelText('Reason'), 'only owner')
    // With the reason given, the sixth digit approves on its own.
    await user.type(screen.getByLabelText('Code from your authenticator app'), '123456')
    await waitFor(() => expect(api.selfApprove).toHaveBeenCalledWith('r1', 'only owner', '123456'))
  })
})

describe('Scan list badge', () => {
  it('shows a waiting scan, nothing for an approved one', () => {
    const { rerender } = render(<ScanApprovalBadge status="pending" />)
    expect(screen.getByText('Awaiting approval')).toBeInTheDocument()
    rerender(<ScanApprovalBadge status="approved" />)
    expect(screen.queryByTestId('scan-approval-badge')).not.toBeInTheDocument()
  })
})
