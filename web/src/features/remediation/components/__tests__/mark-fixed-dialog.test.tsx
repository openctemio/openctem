/**
 * MarkFixedDialog (remediation group and campaign "mark fixed"):
 * - no "close now" outcome is offered: the action only marks findings fixed
 * - the note is required, and the action needs findings:fix_apply
 * - every finding not updated is shown with its reason (no silent failure)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MarkFixedDialog } from '../mark-fixed-dialog'

let canFixApply = true
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => canFixApply }),
}))
vi.mock('sonner', () => ({
  toast: { success: vi.fn(), info: vi.fn(), error: vi.fn() },
}))

const onSubmit = vi.fn()

function renderDialog() {
  return render(
    <MarkFixedDialog
      open
      onOpenChange={() => {}}
      title="Mark the group fixed"
      description="3 open findings"
      openCount={3}
      submitting={false}
      onSubmit={onSubmit}
    />
  )
}

describe('MarkFixedDialog', () => {
  beforeEach(() => {
    canFixApply = true
    onSubmit.mockReset()
  })

  it('offers no close-now outcome and needs a note', async () => {
    renderDialog()
    expect(screen.queryByText(/close now/i)).not.toBeInTheDocument()
    const submit = screen.getByRole('button', { name: 'Mark fixed' })
    expect(submit).toBeDisabled()
    await userEvent.type(screen.getByRole('textbox'), 'patched')
    expect(submit).toBeEnabled()
  })

  it('is disabled without findings:fix_apply', async () => {
    canFixApply = false
    renderDialog()
    await userEvent.type(screen.getByRole('textbox'), 'patched')
    expect(screen.getByRole('button', { name: 'Mark fixed' })).toBeDisabled()
    expect(screen.getByText('You need the permission to mark findings fixed.')).toBeInTheDocument()
  })

  it('lists every finding not updated with the reason', async () => {
    onSubmit.mockResolvedValue({
      updated: 1,
      skipped: 1,
      failed: 1,
      validations_queued: 1,
      rows: [
        { finding_id: 'aaaaaaaa-1', outcome: 'skipped', reason: 'already fix_applied' },
        { finding_id: 'bbbbbbbb-2', outcome: 'failed', reason: 'not yours' },
      ],
    })
    renderDialog()
    await userEvent.type(screen.getByRole('textbox'), 'patched')
    await userEvent.click(screen.getByRole('button', { name: 'Mark fixed' }))
    expect(onSubmit).toHaveBeenCalledWith({ resolution: 'patched', approved: undefined })
    expect(await screen.findByTestId('mark-fixed-result')).toBeInTheDocument()
    expect(screen.getByText(/already fix_applied/)).toBeInTheDocument()
    expect(screen.getByText(/not yours/)).toBeInTheDocument()
  })
})
