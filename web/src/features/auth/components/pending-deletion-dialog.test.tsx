import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const cancelAction = vi.fn()
vi.mock('../actions/local-auth-actions', () => ({
  cancelOrganizationDeletionAction: (...a: unknown[]) => cancelAction(...a),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { PendingDeletionDialog } from './pending-deletion-dialog'

const acme = {
  id: 't1',
  slug: 'acme',
  name: 'Acme',
  role: 'owner',
  organization_suspended: true,
  deletion_due_at: '2026-11-01T09:00:00Z',
}

describe('PendingDeletionDialog', () => {
  beforeEach(() => vi.clearAllMocks())

  it('cancels the deletion and reports the reopened organization', async () => {
    const user = userEvent.setup()
    const onCancelled = vi.fn()
    cancelAction.mockResolvedValue({ success: true })
    render(
      <PendingDeletionDialog
        organizations={[acme]}
        onCancelled={onCancelled}
        onContinue={vi.fn()}
      />
    )
    expect(screen.getByText('Acme')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Cancel deletion' }))
    await waitFor(() => expect(cancelAction).toHaveBeenCalledWith('t1'))
    await waitFor(() => expect(onCancelled).toHaveBeenCalledWith(acme))
  })

  it('stays open when the cancel is refused, and can continue without it', async () => {
    const user = userEvent.setup()
    const onCancelled = vi.fn()
    const onContinue = vi.fn()
    cancelAction.mockResolvedValue({
      success: false,
      error: 'Only an owner of the organization can do this.',
    })
    render(
      <PendingDeletionDialog
        organizations={[acme]}
        onCancelled={onCancelled}
        onContinue={onContinue}
      />
    )
    await user.click(screen.getByRole('button', { name: 'Cancel deletion' }))
    await waitFor(() => expect(cancelAction).toHaveBeenCalled())
    expect(onCancelled).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Continue without it' }))
    expect(onContinue).toHaveBeenCalled()
  })
})
