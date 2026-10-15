import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FindingApprovalSettingsForm } from '../finding-approval-settings-form'

const update = vi.fn()
vi.mock('../../api/use-findings-api', () => ({
  updateFindingApprovalSettings: (...args: unknown[]) => update(...args),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

describe('FindingApprovalSettingsForm', () => {
  beforeEach(() => update.mockReset())

  it('saves the backup contact', async () => {
    update.mockResolvedValue({ backup_contact_email: 'advisor@example.com' })
    const onSaved = vi.fn()
    render(
      <FindingApprovalSettingsForm
        settings={{ backup_contact_email: '' }}
        canEdit
        onSaved={onSaved}
      />
    )
    const save = screen.getByRole('button', { name: /save changes/i })
    expect(save).toBeDisabled()
    await userEvent.type(screen.getByLabelText(/email address/i), 'advisor@example.com')
    await userEvent.click(save)
    expect(update).toHaveBeenCalledWith({ backup_contact_email: 'advisor@example.com' })
    expect(onSaved).toHaveBeenCalledWith({ backup_contact_email: 'advisor@example.com' })
  })

  it('is read-only without settings:write', () => {
    render(
      <FindingApprovalSettingsForm
        settings={{ backup_contact_email: 'a@example.com' }}
        canEdit={false}
      />
    )
    expect(screen.getByLabelText(/email address/i)).toBeDisabled()
    expect(screen.queryByRole('button', { name: /save changes/i })).not.toBeInTheDocument()
  })
})
