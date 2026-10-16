/**
 * The task exception dialog: the live preview (group tier, members with their
 * tier and end, shortened and skipped markers), the note's minimum length
 * from the preview, and the request with its 409 (pending exception).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { toast } from 'sonner'
import { ApiClientError } from '@/lib/api/error-handler'
import { GroupExceptionDialog } from '../group-exception-dialog'

const api = vi.hoisted(() => ({ preview: vi.fn(), request: vi.fn() }))
vi.mock('../../api/use-approval-batches', () => ({ approvalBatchApi: api }))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

// The Reason select scrolls its options into view; jsdom has no layout.
if (!Element.prototype.scrollIntoView) Element.prototype.scrollIntoView = () => {}

const evaluation = {
  kind: 'accepted',
  tier: 'security',
  floor: 'peer',
  risk_class: 'high',
  approvals_required: 1,
  reasons: ['group_decision', 'kev'],
  security_pool: true,
  security_pool_fallback: false,
  step_up: false,
  eligible_approvers: 4,
  eligible_security_pool: 2,
  satisfiable: true,
  min_note_length: 20,
  max_acceptance_days: 30,
  decide_within_days: 7,
}

const preview = {
  evaluation,
  members: [
    {
      finding_id: 'f-1',
      title: 'Outdated TLS on api.example.com',
      severity: 'high',
      tier: 'security',
      risk_class: 'high',
      end: '2026-11-15T00:00:00Z',
      shortened: true,
    },
    {
      finding_id: 'f-2',
      title: 'Directory listing',
      severity: 'low',
      tier: 'peer',
      risk_class: 'standard',
      end: '2026-12-01T00:00:00Z',
    },
    { finding_id: 'f-3', title: 'Old banner', severity: 'medium', skipped: 'pending_request' },
  ],
  included: 2,
  skipped: 1,
}

async function chooseReason(user: ReturnType<typeof userEvent.setup>, label: string) {
  await user.click(screen.getByRole('combobox'))
  await user.click(await screen.findByRole('option', { name: label }))
}

function renderDialog(extra: Partial<React.ComponentProps<typeof GroupExceptionDialog>> = {}) {
  const props = {
    taskId: 'task-1',
    open: true,
    onOpenChange: vi.fn(),
    onCreated: vi.fn(),
    onPendingConflict: vi.fn(),
    ...extra,
  }
  render(<GroupExceptionDialog {...props} />)
  return props
}

describe('GroupExceptionDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.preview.mockResolvedValue(preview)
  })

  it('asks for a reason before previewing', () => {
    renderDialog()
    expect(screen.getByText(/Choose a reason to see who decides/)).toBeInTheDocument()
    expect(api.preview).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Request exception' })).toBeDisabled()
  })

  it('previews the group: tier and why, members with shortened and skipped markers', async () => {
    const user = userEvent.setup()
    renderDialog()
    await chooseReason(user, 'Risk accepted')

    await waitFor(() => expect(api.preview).toHaveBeenCalledTimes(1))
    const [taskId, body] = api.preview.mock.calls[0]
    expect(taskId).toBe('task-1')
    expect(body.requested_status).toBe('accepted')
    expect(body.closure_reason).toBe('risk_accepted')
    expect(typeof body.expires_at).toBe('string')

    const banner = await screen.findByTestId('approval-evaluation')
    expect(banner).toHaveTextContent('Security')
    expect(banner).toHaveTextContent(/at most 30 days/)
    expect(screen.getByText('2 finding(s) covered, 1 left out.')).toBeInTheDocument()

    const rows = screen.getAllByTestId('group-exception-member')
    expect(rows).toHaveLength(3)
    expect(within(rows[0]).getByText('Shortened to its limit')).toBeInTheDocument()
    expect(within(rows[1]).queryByText('Shortened to its limit')).not.toBeInTheDocument()
    expect(within(rows[2]).getByText('Has a pending request')).toBeInTheDocument()
    expect(within(rows[0]).getByRole('link')).toHaveAttribute('href', '/findings/f-1')
  })

  it("enforces the preview's minimum note length", async () => {
    const user = userEvent.setup()
    renderDialog()
    await chooseReason(user, 'Risk accepted')
    await screen.findByTestId('approval-evaluation')

    const note = screen.getByLabelText('Justification')
    await user.type(note, 'too short')
    expect(screen.getByRole('alert')).toHaveTextContent('Write at least 20 characters')
    expect(screen.getByRole('button', { name: 'Request exception' })).toBeDisabled()

    await user.type(note, ' but now it is long enough')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Request exception' })).toBeEnabled()
  })

  it('requests the exception and reports it', async () => {
    const user = userEvent.setup()
    api.request.mockResolvedValue({ id: 'b-1', member_count: 2, tier: 'security' })
    const props = renderDialog()
    await chooseReason(user, 'Risk accepted')
    await screen.findByTestId('approval-evaluation')
    await user.type(
      screen.getByLabelText('Justification'),
      '  No maintenance window until December  '
    )
    await user.click(screen.getByRole('button', { name: 'Request exception' }))

    await waitFor(() => expect(api.request).toHaveBeenCalledTimes(1))
    const body = api.request.mock.calls[0][1]
    expect(body.justification).toBe('No maintenance window until December')
    expect(body.closure_reason).toBe('risk_accepted')
    expect(toast.success).toHaveBeenCalledWith('Exception requested', expect.anything())
    expect(props.onOpenChange).toHaveBeenCalledWith(false)
    expect(props.onCreated).toHaveBeenCalled()
  })

  it('explains a pending exception (409) and refreshes the task', async () => {
    const user = userEvent.setup()
    api.request.mockRejectedValue(new ApiClientError('pending', 'CONFLICT', 409))
    const props = renderDialog()
    await chooseReason(user, 'Risk accepted')
    await screen.findByTestId('approval-evaluation')
    await user.type(screen.getByLabelText('Justification'), 'A long enough justification here')
    await user.click(screen.getByRole('button', { name: 'Request exception' }))

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        'This task already has a pending exception. Decide or cancel it first.'
      )
    )
    expect(props.onPendingConflict).toHaveBeenCalled()
  })

  it('asks to confirm a group above the bulk ceiling, then resends it with approved: true', async () => {
    const user = userEvent.setup()
    api.request
      .mockRejectedValueOnce(new ApiClientError('bulk', 'BULK_TOO_LARGE', 400))
      .mockResolvedValueOnce({ id: 'b-1', member_count: 600, tier: 'security' })
    const props = renderDialog()
    await chooseReason(user, 'Risk accepted')
    await screen.findByTestId('approval-evaluation')
    await user.type(screen.getByLabelText('Justification'), 'A long enough justification here')
    await user.click(screen.getByRole('button', { name: 'Request exception' }))

    expect(await screen.findByTestId('group-exception-bulk-confirm')).toBeInTheDocument()
    expect(api.request.mock.calls[0][1].approved).toBeUndefined()
    expect(props.onOpenChange).not.toHaveBeenCalledWith(false)
    expect(toast.error).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: 'Confirm and request' }))
    await waitFor(() => expect(api.request).toHaveBeenCalledTimes(2))
    expect(api.request.mock.calls[1][1].approved).toBe(true)
    expect(props.onCreated).toHaveBeenCalled()
  })

  it('a false positive offers its own reasons and sends no end date', async () => {
    const user = userEvent.setup()
    api.preview.mockResolvedValue({
      ...preview,
      evaluation: { ...evaluation, kind: 'false_positive', max_acceptance_days: 0 },
    })
    renderDialog()
    await user.click(screen.getByLabelText('False positive'))
    expect(screen.queryByLabelText('Acceptance expires on')).not.toBeInTheDocument()
    await chooseReason(user, 'Test or example code')

    await waitFor(() => expect(api.preview).toHaveBeenCalled())
    const body = api.preview.mock.calls.at(-1)![1]
    expect(body.requested_status).toBe('false_positive')
    expect(body.expires_at).toBeUndefined()
  })
})
