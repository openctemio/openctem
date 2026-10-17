/**
 * A group exception in the approvals inbox: the members, and the decision
 * with the same response handling as a single approval (more sign-offs
 * needed, applied with canceled members, refusal reasons, already decided),
 * a rejection that needs a reason, and cancel offered to the requester only.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { toast } from 'sonner'
import { ApiClientError } from '@/lib/api/error-handler'
import { GroupExceptionSheet } from '../group-exceptions-panel'

const api = vi.hoisted(() => ({ approve: vi.fn(), reject: vi.fn(), cancel: vi.fn() }))
const state = vi.hoisted(() => ({ batch: null as Record<string, unknown> | null }))
const mockMutate = vi.fn()
vi.mock('../../api/use-approval-batches', () => ({
  approvalBatchApi: api,
  useApprovalBatch: () => ({
    data: state.batch,
    error: null,
    isLoading: false,
    mutate: mockMutate,
  }),
  useApprovalBatches: () => ({ data: null, isLoading: false, mutate: vi.fn() }),
}))

vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => children,
  Permission: { FindingsApprove: 'findings:approve', FindingsWrite: 'findings:write' },
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const pendingBatch = {
  id: 'b-1',
  source_type: 'task',
  source_id: 't-1',
  source_title: 'Patch OpenSSL on edge hosts',
  requested_status: 'accepted',
  closure_reason: 'risk_accepted',
  justification: 'No maintenance window until December',
  expires_at: '2026-12-01T00:00:00Z',
  requested_by: 'requester-1',
  tier: 'dual',
  risk_class: 'critical',
  approvals_required: 2,
  approvals_collected: 0,
  status: 'pending',
  decide_by: '2026-10-23T00:00:00Z',
  member_count: 2,
  created_at: '2026-10-16T00:00:00Z',
  members: [
    {
      approval_id: 'a-1',
      finding_id: 'f-1',
      title: 'OpenSSL CVE on edge-1',
      severity: 'critical',
      status: 'pending',
      expires_at: '2026-11-15T00:00:00Z',
    },
    {
      approval_id: 'a-2',
      finding_id: 'f-2',
      title: 'OpenSSL CVE on edge-2',
      severity: 'high',
      status: 'pending',
    },
  ],
}

function renderSheet(currentUserId = 'approver-1') {
  const onDecided = vi.fn()
  render(
    <GroupExceptionSheet
      id="b-1"
      onOpenChange={vi.fn()}
      currentUserId={currentUserId}
      onDecided={onDecided}
    />
  )
  return { onDecided }
}

describe('GroupExceptionSheet', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    state.batch = { ...pendingBatch }
  })

  it('lists the members and links the task', () => {
    renderSheet()
    expect(screen.getByRole('link', { name: 'Patch OpenSSL on edge hosts' })).toHaveAttribute(
      'href',
      '/remediation/tasks/t-1'
    )
    expect(screen.getByText('OpenSSL CVE on edge-1')).toBeInTheDocument()
    expect(screen.getByText('OpenSSL CVE on edge-2')).toBeInTheDocument()
    expect(screen.getByText('0 of 2 approvals')).toBeInTheDocument()
  })

  it('records a sign-off while more are needed', async () => {
    const user = userEvent.setup()
    api.approve.mockResolvedValue({ ...pendingBatch, approvals_collected: 1 })
    const { onDecided } = renderSheet()
    await user.click(screen.getByRole('button', { name: 'Add my approval' }))
    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith('Your approval is recorded', {
        description: '1 more approval(s) needed before the findings change.',
      })
    )
    expect(onDecided).toHaveBeenCalled()
  })

  it('reports the applied members and the ones canceled because they moved', async () => {
    const user = userEvent.setup()
    state.batch = { ...pendingBatch, approvals_required: 1 }
    api.approve.mockResolvedValue({
      ...pendingBatch,
      status: 'approved',
      approvals_collected: 1,
      approvals_required: 1,
      applied: 1,
      canceled: ['f-2'],
    })
    renderSheet()
    await user.click(screen.getByRole('button', { name: 'Approve 2 finding(s)' }))
    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith('Group exception approved', {
        description:
          '1 finding(s) moved to Accepted risk. 1 left out because they changed meanwhile.',
      })
    )
  })

  it('shows why an approver is refused', async () => {
    const user = userEvent.setup()
    api.approve.mockRejectedValue(
      new ApiClientError('refused', 'APPROVER_NOT_ELIGIBLE', 403, { reason: 'asset_owner' })
    )
    renderSheet()
    await user.click(screen.getByRole('button', { name: 'Add my approval' }))
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        "You own this finding's asset, so you cannot approve hiding its risk."
      )
    )
  })

  it('says when the group was already decided', async () => {
    const user = userEvent.setup()
    api.approve.mockRejectedValue(new ApiClientError('gone', 'BATCH_NOT_PENDING', 409))
    renderSheet()
    await user.click(screen.getByRole('button', { name: 'Add my approval' }))
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        'This group exception was already decided, canceled or expired.'
      )
    )
  })

  it('a cancelled identity confirmation ends with the step-up message', async () => {
    const user = userEvent.setup()
    api.approve.mockRejectedValue(new ApiClientError('step up', 'STEP_UP_REQUIRED', 403))
    renderSheet()
    await user.click(screen.getByRole('button', { name: 'Add my approval' }))
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith('Confirm your identity to approve this request.')
    )
  })

  it('rejects only with a reason', async () => {
    const user = userEvent.setup()
    api.reject.mockResolvedValue({ ...pendingBatch, status: 'rejected' })
    renderSheet()
    await user.click(screen.getByRole('button', { name: 'Reject' }))
    const dialog = await screen.findByRole('dialog', { name: 'Reject group exception' })
    const confirm = Array.from(dialog.querySelectorAll('button')).find(
      (b) => b.textContent === 'Reject'
    )!
    expect(confirm).toBeDisabled()
    await user.type(screen.getByRole('textbox'), 'Compensating control is not in place')
    expect(confirm).toBeEnabled()
    await user.click(confirm)
    await waitFor(() =>
      expect(api.reject).toHaveBeenCalledWith('b-1', 'Compensating control is not in place')
    )
  })

  it('offers cancel to the requester only, and no decision on their own request', () => {
    renderSheet('requester-1')
    expect(screen.getByRole('button', { name: 'Cancel request' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Add my approval' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Reject' })).not.toBeInTheDocument()
  })

  it('an approver gets no cancel', () => {
    renderSheet('approver-1')
    expect(screen.queryByRole('button', { name: 'Cancel request' })).not.toBeInTheDocument()
  })

  it('a decided group offers no action', () => {
    state.batch = { ...pendingBatch, status: 'approved' }
    renderSheet()
    expect(screen.queryByRole('button', { name: 'Add my approval' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Reject' })).not.toBeInTheDocument()
  })
})
