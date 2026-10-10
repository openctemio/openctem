/**
 * The console's scope approval policy (RFC-054 §12.6): a super admin saves
 * a mode with a reason and an authenticator code; anyone else reads it; an
 * organization may follow the platform default.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { ScopePolicyForm } = await import('../components/scope-policy-form')

describe('ScopePolicyForm', () => {
  it('is read-only without the super admin role', () => {
    render(
      <ScopePolicyForm
        title="Platform default"
        description="d"
        value="required"
        canEdit={false}
        onSave={vi.fn()}
      />
    )
    expect(screen.getByText('Only a super admin can change it.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
  })

  it('saves a new mode with a reason and a code', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(
      <ScopePolicyForm
        title="Platform default"
        description="d"
        value="required"
        canEdit
        onSave={onSave}
      />
    )
    await user.click(screen.getByLabelText(/No approvals/))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await user.type(await screen.findByLabelText('Reason'), 'lab deployment')
    await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(onSave).toHaveBeenCalledWith('disabled', 'lab deployment', '123456'))
  })

  it('lets an organization follow the platform default', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(
      <ScopePolicyForm
        title="Scope approvals"
        description="d"
        value="disabled"
        platformDefault="required"
        canEdit
        onSave={onSave}
      />
    )
    expect(screen.getByText(/Now: Approvals required/)).toBeInTheDocument()
    await user.click(screen.getByLabelText(/Follow the platform default/))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await user.type(await screen.findByLabelText('Reason'), 'back to default')
    await user.type(screen.getByLabelText('Code from your authenticator'), '654321')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(onSave).toHaveBeenCalledWith(null, 'back to default', '654321'))
  })
})
