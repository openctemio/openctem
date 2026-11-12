/**
 * The reason and the one-time authenticator code of a console confirmation
 * never outlive the dialog: reopening after Cancel, after a refused code or
 * after a saved change shows empty fields and no stale error. The state lives
 * in useReasonAndCode, shared by every console confirmation that asks for it.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AdminApiError } from '@console/lib/admin-api/client'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { ScanPolicyForm } = await import('../components/scan-policy-form')

const REASON = 'Reason'
const CODE = 'Code from your authenticator app'

function setup(onSave: (p: unknown, reason: string, code: string) => Promise<void>) {
  const user = userEvent.setup()
  render(
    <ScanPolicyForm
      title="Platform default"
      description="d"
      value="tenant_controlled"
      canEdit
      onSave={onSave}
    />
  )
  const open = async () => {
    // A change is needed before Save is offered; pick Strict once.
    const strict = screen.getByLabelText(/^Strict/)
    if (strict.getAttribute('data-state') !== 'checked') await user.click(strict)
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    return screen.findByLabelText(REASON)
  }
  return { user, open }
}

describe('reason and code in a console confirmation', () => {
  it('marks the reason as required and puts the cursor in it on open', async () => {
    const { open } = setup(vi.fn())
    const reason = await open()
    expect(reason).toBeRequired()
    expect(screen.getByText(/Required: say why you make this change/)).toBeInTheDocument()
    await waitFor(() => expect(reason).toHaveFocus())
  })

  it('reopens empty after Cancel', async () => {
    const { user, open } = setup(vi.fn())
    await user.type(await open(), 'because')
    await user.type(screen.getByLabelText(CODE), '123456')
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByLabelText(REASON)).toBeNull())
    const reason = await open()
    expect(reason).toHaveValue('')
    expect(screen.getByLabelText(CODE)).toHaveValue('')
  })

  it('reopens empty and without the old error after a refused code', async () => {
    const onSave = vi
      .fn()
      .mockRejectedValueOnce(
        new AdminApiError('Invalid or already used code', 401, 'ADMIN_STEP_UP_REQUIRED')
      )
    const { user, open } = setup(onSave)
    await user.type(await open(), 'because')
    await user.type(screen.getByLabelText(CODE), '123456')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByText('Invalid or already used code')).toBeInTheDocument()
    // The used code is cleared at once; the reason stays for the retry.
    expect(screen.getByLabelText(CODE)).toHaveValue('')
    expect(screen.getByLabelText(REASON)).toHaveValue('because')
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByLabelText(REASON)).toBeNull())
    const reason = await open()
    expect(reason).toHaveValue('')
    expect(screen.getByLabelText(CODE)).toHaveValue('')
    expect(screen.queryByText('Invalid or already used code')).toBeNull()
  })

  it('a confirmed change clears both', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    const { user, open } = setup(onSave)
    await user.type(await open(), 'regulated customer')
    await user.type(screen.getByLabelText(CODE), '123456')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() =>
      expect(onSave).toHaveBeenCalledWith('strict', 'regulated customer', '123456')
    )
    await waitFor(() => expect(screen.queryByLabelText(REASON)).toBeNull())
    const reason = await open()
    expect(reason).toHaveValue('')
    expect(screen.getByLabelText(CODE)).toHaveValue('')
  })
})
