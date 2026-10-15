import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ExposureEvent } from '@/lib/api/exposure-types'

const acceptExposure = vi.fn()
const markExposureFalsePositive = vi.fn()
const rejectExposureDisposition = vi.fn()
vi.mock('../../hooks/use-exposures', () => ({
  acceptExposure: (...a: unknown[]) => acceptExposure(...a),
  markExposureFalsePositive: (...a: unknown[]) => markExposureFalsePositive(...a),
  rejectExposureDisposition: (...a: unknown[]) => rejectExposureDisposition(...a),
  resolveExposure: vi.fn(),
  reactivateExposure: vi.fn(),
}))
let canApprove = true
vi.mock('../exposure-state-actions', () => ({
  useCanApproveExposures: () => canApprove,
}))
vi.mock('@/stores/auth-store', () => ({
  useAuthStore: (sel: (s: { user: { id: string } }) => unknown) => sel({ user: { id: 'me' } }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn(), info: vi.fn() } }))

import { PendingDispositionPanel } from '../pending-disposition'

const exposure = (
  requestedBy: string,
  state: 'accepted' | 'false_positive',
  selfApprovalAvailable = false
): ExposureEvent =>
  ({
    id: 'exp-1',
    title: 'Open port',
    severity: 'high',
    state: 'active',
    pending_disposition: {
      id: 'req-1',
      requested_state: state,
      requested_by: requestedBy,
      reason: '<img src=x onerror=alert(1)>',
      created_at: '2026-10-14T00:00:00Z',
      self_approval_available: selfApprovalAvailable,
    },
  }) as unknown as ExposureEvent

describe('PendingDispositionPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    canApprove = true
  })

  it('lets a different approver confirm the requested disposition', async () => {
    const onChanged = vi.fn()
    render(
      <PendingDispositionPanel
        exposure={exposure('other', 'false_positive')}
        onChanged={onChanged}
      />
    )
    expect(screen.getByText('Waiting for a second approver')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Approve/ }))
    expect(markExposureFalsePositive).toHaveBeenCalledWith('exp-1')
    expect(acceptExposure).not.toHaveBeenCalled()
    expect(onChanged).toHaveBeenCalled()
  })

  it('never offers Approve on your own request, only Cancel', async () => {
    render(<PendingDispositionPanel exposure={exposure('me', 'accepted')} />)
    expect(screen.queryByRole('button', { name: /Approve/ })).toBeNull()
    expect(screen.getByText('A different approver must confirm your request.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Cancel request/ }))
    expect(rejectExposureDisposition).toHaveBeenCalledWith('exp-1')
  })

  it('shows no actions without approval rights and renders the reason as text', () => {
    canApprove = false
    const { container } = render(
      <PendingDispositionPanel exposure={exposure('other', 'accepted')} />
    )
    expect(screen.queryByRole('button')).toBeNull()
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
  })

  it('lets a lone owner approve their own request only with a reason and a code', async () => {
    render(<PendingDispositionPanel exposure={exposure('me', 'accepted', true)} />)
    expect(screen.queryByRole('button', { name: /^Approve$/ })).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: /Approve my own request/ }))
    const submit = screen.getByRole('button', { name: /^Approve$/ })
    expect(submit).toBeDisabled()
    await userEvent.type(screen.getByLabelText(/without a second person/), 'only member')
    await userEvent.type(screen.getByLabelText(/authenticator app/), '123456')
    await userEvent.click(submit)
    expect(acceptExposure).toHaveBeenCalledWith('exp-1', {
      reason: 'only member',
      self_approve: true,
      totp_code: '123456',
    })
  })

  it('offers no own approval when the API says it is not available', () => {
    render(<PendingDispositionPanel exposure={exposure('me', 'accepted', false)} />)
    expect(screen.queryByRole('button', { name: /Approve my own request/ })).toBeNull()
  })
})
