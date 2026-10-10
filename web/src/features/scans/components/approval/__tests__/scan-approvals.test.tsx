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
  list: { data: [] as ScanApprovalRequest[], total: 0 },
  approve: vi.fn(),
  reject: vi.fn(),
  selfApprove: vi.fn(),
  mutate: vi.fn(),
}))
vi.mock('@/lib/api/scan-approval-hooks', () => ({
  useScanApprovals: () => ({
    data: api.list,
    error: undefined,
    isLoading: false,
    mutate: api.mutate,
  }),
  approveScanRequest: api.approve,
  rejectScanRequest: api.reject,
  selfApproveScanRequest: api.selfApprove,
  remindScanApprovers: vi.fn(),
  cancelScanRequest: vi.fn(),
}))
vi.mock('@/stores/auth-store', () => ({
  useAuthStore: (sel: (s: { user: { id: string } }) => unknown) => sel({ user: { id: 'me' } }),
}))
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
  it('approves with a note when the API allows the viewer', async () => {
    api.list = { data: [request()], total: 1 }
    api.approve.mockResolvedValue(request({ status: 'approved' }))
    const user = userEvent.setup()
    render(<ScanApprovalsInbox />)
    expect(screen.getByText('Web pentest')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Show details' }))
    expect(screen.getByText('Changed since the last approval')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Approve' }))
    await user.type(await screen.findByLabelText('Note (optional)'), 'ok')
    const buttons = screen.getAllByRole('button', { name: 'Approve' })
    await user.click(buttons[buttons.length - 1])
    await waitFor(() => expect(api.approve).toHaveBeenCalledWith('r1', 'ok'))
  })

  it('offers no decision when the API says the viewer may not approve', () => {
    api.list = { data: [request({ can_approve: false })], total: 1 }
    render(<ScanApprovalsInbox />)
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Reject' })).not.toBeInTheDocument()
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
    expect(screen.getByRole('button', { name: 'Remind' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /Approve my own scan/ }))
    const confirm = screen.getAllByRole('button', { name: 'Approve' }).pop()!
    expect(confirm).toBeDisabled()
    await user.type(screen.getByLabelText('Reason'), 'only owner')
    await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
    await user.click(confirm)
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
