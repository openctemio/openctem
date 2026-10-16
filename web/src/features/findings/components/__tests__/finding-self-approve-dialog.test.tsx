import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FindingSelfApproveDialog, selfApproveErrorMessage } from '../finding-self-approve-dialog'
import type { ApiApproval } from '../../types/finding.types'

const selfApprove = vi.fn()
vi.mock('../../api/use-findings-api', () => ({
  selfApproveFindingApproval: (...args: unknown[]) => selfApprove(...args),
}))
const toastSuccess = vi.fn()
vi.mock('sonner', () => ({ toast: { success: (m: string) => toastSuccess(m), error: vi.fn() } }))

const approval = {
  id: 'a-1',
  tenant_id: 't',
  finding_id: 'f',
  requested_status: 'accepted',
  requested_by: 'u',
  justification: 'x',
  status: 'pending',
  created_at: '2026-10-15T00:00:00Z',
} as ApiApproval

const t = (_k: string, fallback?: string) => fallback ?? _k

describe('FindingSelfApproveDialog', () => {
  beforeEach(() => {
    selfApprove.mockReset()
    toastSuccess.mockReset()
  })

  it('renders nothing without a request', () => {
    const { container } = render(
      <FindingSelfApproveDialog approval={null} onOpenChange={vi.fn()} />
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('says what happens and needs a reason and a code before submitting', async () => {
    render(<FindingSelfApproveDialog approval={approval} onOpenChange={vi.fn()} />)
    expect(screen.getByText(/recorded in the audit log/i)).toBeInTheDocument()
    expect(screen.getByText(/backup contact are told/i)).toBeInTheDocument()
    expect(screen.getByText(/within 7 days/i)).toBeInTheDocument()
    const submit = screen.getByRole('button', { name: 'Approve' })
    expect(submit).toBeDisabled()
    await userEvent.type(screen.getByLabelText(/second person/i), 'one-person company')
    await userEvent.type(screen.getByLabelText(/authenticator app/i), '12 34 56')
    expect(submit).toBeEnabled()
  })

  it('submits the reason and the code and tells when the end was shortened', async () => {
    selfApprove.mockResolvedValue({ ...approval, status: 'approved', end_shortened: true })
    const onOpenChange = vi.fn()
    const onApproved = vi.fn()
    render(
      <FindingSelfApproveDialog
        approval={approval}
        onOpenChange={onOpenChange}
        onApproved={onApproved}
      />
    )
    await userEvent.type(screen.getByLabelText(/second person/i), 'reviewed the trace')
    await userEvent.type(screen.getByLabelText(/authenticator app/i), '123456')
    await userEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(selfApprove).toHaveBeenCalledWith('a-1', {
      reason: 'reviewed the trace',
      code: '123456',
    })
    expect(toastSuccess).toHaveBeenCalledWith(expect.stringMatching(/shortened/i))
    expect(onApproved).toHaveBeenCalled()
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it('shows the refusal and clears the code', async () => {
    selfApprove.mockRejectedValue({ code: 'SELF_APPROVAL_INVALID_CODE', message: 'x' })
    render(<FindingSelfApproveDialog approval={approval} onOpenChange={vi.fn()} />)
    await userEvent.type(screen.getByLabelText(/second person/i), 'r')
    const code = screen.getByLabelText(/authenticator app/i)
    await userEvent.type(code, '000000')
    await userEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/wrong or was already used/i)
    expect(code).toHaveValue('')
  })

  it('maps every refusal code, else the server message', () => {
    expect(selfApproveErrorMessage(t, { code: 'SELF_APPROVAL_NOT_ALLOWED' })).toMatch(
      /no other active member/
    )
    expect(selfApproveErrorMessage(t, { code: 'SELF_APPROVAL_NEEDS_TOTP' })).toMatch(/two-factor/)
    expect(selfApproveErrorMessage(t, { code: 'OTHER', message: 'server says' })).toBe(
      'server says'
    )
    expect(selfApproveErrorMessage(t, null)).toMatch(/Could not approve/)
  })
})
