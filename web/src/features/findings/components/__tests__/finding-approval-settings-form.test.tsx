import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FindingApprovalSettingsForm } from '../finding-approval-settings-form'

// The radio group measures itself; jsdom has no ResizeObserver.
if (!('ResizeObserver' in globalThis)) {
  ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}

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

describe('FindingApprovalSettingsForm — false-positive level', () => {
  beforeEach(() => update.mockReset())

  it('warns on off and says a lowering waits 24 hours', async () => {
    update.mockResolvedValue({
      backup_contact_email: '',
      fp_approval: 'all',
      pending_fp_approval: 'off',
    })
    render(
      <FindingApprovalSettingsForm
        settings={{ backup_contact_email: '', fp_approval: 'all' }}
        canEdit
      />
    )
    expect(screen.queryByText(/one person can hide any finding/i)).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('radio', { name: /never/i }))
    expect(screen.getByText(/one person can hide any finding/i)).toBeInTheDocument()
    expect(screen.getByText(/takes effect 24 hours after you save/i)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /save changes/i }))
    expect(update).toHaveBeenCalledWith({ fp_approval: 'off' })
  })

  it('shows a waiting lowering with its time, and choosing the level in force cancels it', async () => {
    update.mockResolvedValue({ backup_contact_email: '', fp_approval: 'all' })
    render(
      <FindingApprovalSettingsForm
        settings={{
          backup_contact_email: '',
          fp_approval: 'all',
          pending_fp_approval: 'high_and_above',
          pending_fp_approval_at: '2026-10-16T12:00:00Z',
        }}
        canEdit
      />
    )
    expect(screen.getByText(/a lower level is waiting/i)).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: /only for serious findings/i })).toBeChecked()
    await userEvent.click(screen.getByRole('radio', { name: /always/i }))
    await userEvent.click(screen.getByRole('button', { name: /save changes/i }))
    expect(update).toHaveBeenCalledWith({ fp_approval: 'all' })
  })

  it('keeps the second-look share within 0 to 10', async () => {
    render(
      <FindingApprovalSettingsForm
        settings={{ backup_contact_email: '', fp_approval: 'off' }}
        canEdit
      />
    )
    const input = screen.getByLabelText(/second look/i)
    await userEvent.clear(input)
    await userEvent.type(input, '55')
    expect(input).toHaveValue(10)
  })

  it('cancels a waiting level lowering with one click', async () => {
    update.mockResolvedValue({ backup_contact_email: '', fp_approval: 'all' })
    const onSaved = vi.fn()
    render(
      <FindingApprovalSettingsForm
        settings={{
          backup_contact_email: '',
          fp_approval: 'all',
          pending_fp_approval: 'off',
          pending_fp_approval_at: '2026-10-16T12:00:00Z',
        }}
        canEdit
        onSaved={onSaved}
      />
    )
    await userEvent.click(screen.getByRole('button', { name: /cancel the change/i }))
    expect(update).toHaveBeenCalledWith({ cancel_pending: true })
    expect(onSaved).toHaveBeenCalled()
  })

  it('shows a waiting second-look decrease with its time and cancels it', async () => {
    update.mockResolvedValue({
      backup_contact_email: '',
      fp_approval: 'off',
      second_look_percent: 5,
    })
    render(
      <FindingApprovalSettingsForm
        settings={{
          backup_contact_email: '',
          fp_approval: 'off',
          second_look_percent: 5,
          pending_second_look_percent: 0,
          pending_second_look_at: '2026-10-16T12:00:00Z',
        }}
        canEdit
      />
    )
    expect(screen.getByText(/a lower second-look share is waiting/i)).toBeInTheDocument()
    expect(screen.getByLabelText(/second look/i)).toHaveValue(0)
    await userEvent.click(screen.getByRole('button', { name: /cancel the change/i }))
    expect(update).toHaveBeenCalledWith({ cancel_pending: true })
  })

  it('hides the cancel button without settings:write', () => {
    render(
      <FindingApprovalSettingsForm
        settings={{
          backup_contact_email: '',
          fp_approval: 'all',
          pending_fp_approval: 'off',
          pending_fp_approval_at: '2026-10-16T12:00:00Z',
          second_look_percent: 5,
          pending_second_look_percent: 0,
          pending_second_look_at: '2026-10-16T12:00:00Z',
        }}
        canEdit={false}
      />
    )
    expect(screen.queryByRole('button', { name: /cancel the change/i })).not.toBeInTheDocument()
  })
})
