/**
 * The console's scan approval policy (RFC-072 §5): a super admin saves a
 * policy with a reason and an authenticator code; anyone else reads it; an
 * organization may follow the platform default.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { ScanPolicyForm } = await import('../components/scan-policy-form')

describe('ScanPolicyForm', () => {
  it('is read-only without the super admin role', () => {
    render(
      <ScanPolicyForm
        title="Platform default"
        description="d"
        value="tenant_controlled"
        canEdit={false}
        onSave={vi.fn()}
      />
    )
    expect(screen.getByText('Only a super admin can change it.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
  })

  it('saves a new policy with a reason and a code', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
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
    await user.click(screen.getByLabelText(/^Strict/))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await user.type(await screen.findByLabelText('Reason'), 'regulated customer')
    await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() =>
      expect(onSave).toHaveBeenCalledWith('strict', 'regulated customer', '123456')
    )
  })

  it('lets an organization follow the platform default', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(
      <ScanPolicyForm
        title="Scan approval"
        description="d"
        value="off"
        platformDefault="tenant_controlled"
        canEdit
        onSave={onSave}
      />
    )
    expect(screen.getByText(/Now: The organization decides/)).toBeInTheDocument()
    await user.click(screen.getByLabelText(/Follow the platform default/))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await user.type(await screen.findByLabelText('Reason'), 'back to default')
    await user.type(screen.getByLabelText('Code from your authenticator'), '654321')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(onSave).toHaveBeenCalledWith(null, 'back to default', '654321'))
  })
})
