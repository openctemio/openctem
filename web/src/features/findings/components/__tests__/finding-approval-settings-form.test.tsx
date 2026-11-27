import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FindingApprovalsForm } from '../finding-approvals-form'
import { openEditor, settingsOf } from './approvals-test-setup'

const update = vi.fn()
vi.mock('../../api/use-findings-api', () => ({
  updateFindingApprovalSettings: (...args: unknown[]) => update(...args),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useGroups: () => ({ groups: [], isLoading: false }),
}))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ can: () => true }),
  Permission: { GroupsRead: 'team:groups:read' },
}))

let user: ReturnType<typeof userEvent.setup>
beforeEach(() => {
  user = userEvent.setup({ delay: null })
  update.mockReset()
})

describe('Approvals editors: the backup contact', () => {
  it('saves the backup contact', async () => {
    update.mockResolvedValue(settingsOf({ backup_contact_email: 'advisor@example.com' }))
    render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    const dialog = await openEditor(user, 'Backup contact')
    await user.type(dialog.getByLabelText(/email address/i), 'advisor@example.com')
    await user.click(dialog.getByRole('button', { name: 'Save' }))
    expect(update).toHaveBeenCalledWith({ backup_contact_email: 'advisor@example.com' })
  })

  it('drops the unsaved change on Cancel', async () => {
    render(
      <FindingApprovalsForm
        settings={settingsOf({ backup_contact_email: 'a@example.com' })}
        canEdit
      />
    )
    let dialog = await openEditor(user, 'Backup contact')
    const email = dialog.getByLabelText(/email address/i)
    await user.clear(email)
    await user.type(email, 'b@example.com')
    await user.click(dialog.getByRole('button', { name: 'Cancel' }))
    await user.click(await screen.findByRole('button', { name: /discard/i }))
    expect(update).not.toHaveBeenCalled()
    expect(document.getElementById('backup-contact')).toHaveTextContent('a@example.com')
    dialog = await openEditor(user, 'Backup contact')
    expect(dialog.getByLabelText(/email address/i)).toHaveValue('a@example.com')
  })

  it('is read-only without settings:write', async () => {
    render(
      <FindingApprovalsForm
        settings={settingsOf({ backup_contact_email: 'a@example.com' })}
        canEdit={false}
      />
    )
    const dialog = await openEditor(user, 'Backup contact', 'View')
    expect(dialog.getByLabelText(/email address/i)).toBeDisabled()
    expect(dialog.queryByRole('button', { name: 'Save' })).toBeNull()
  })
})

describe('Approvals editors: the risk acceptance level', () => {
  it('defaults to a second person for every accepted risk', async () => {
    render(<FindingApprovalsForm settings={settingsOf({ accept_approval: undefined })} canEdit />)
    const dialog = await openEditor(user, 'Accepted risks')
    expect(dialog.getByRole('radio', { name: /always/i })).toBeChecked()
  })

  it('warns on off, says a lowering waits 24 hours, and saves only accept_approval', async () => {
    update.mockResolvedValue(settingsOf({ pending_accept_approval: 'off' }))
    render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    const dialog = await openEditor(user, 'Accepted risks')
    expect(dialog.queryByText(/one person can accept any risk/i)).toBeNull()
    await user.click(dialog.getByRole('radio', { name: /never/i }))
    expect(dialog.getByText(/one person can accept any risk/i)).toBeInTheDocument()
    expect(
      dialog.getByText(/a lower level takes effect 24 hours after you save/i)
    ).toBeInTheDocument()
    await user.click(dialog.getByRole('button', { name: 'Save' }))
    expect(update).toHaveBeenCalledWith({ accept_approval: 'off' })
  })

  it('starts from the waiting lower level and says it waits', async () => {
    render(
      <FindingApprovalsForm
        settings={settingsOf({
          pending_accept_approval: 'high_and_above',
          pending_accept_approval_at: '2026-10-24T12:00:00Z',
        })}
        canEdit
      />
    )
    const dialog = await openEditor(user, 'Accepted risks')
    expect(dialog.getByText(/a lower level is waiting/i)).toBeInTheDocument()
    expect(dialog.getByRole('radio', { name: /only for serious findings/i })).toBeChecked()
  })

  it('is read-only without settings:write', async () => {
    render(
      <FindingApprovalsForm
        settings={settingsOf({
          pending_accept_approval: 'off',
          pending_accept_approval_at: '2026-10-24T12:00:00Z',
        })}
        canEdit={false}
      />
    )
    const dialog = await openEditor(user, 'Accepted risks', 'View')
    expect(dialog.getByRole('radio', { name: /never/i })).toBeDisabled()
  })
})

describe('Approvals editors: the false-positive level', () => {
  it('warns on off and says a lowering waits 24 hours', async () => {
    update.mockResolvedValue(settingsOf({ pending_fp_approval: 'off' }))
    render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    const dialog = await openEditor(user, 'False positives')
    expect(dialog.queryByText(/one person can hide any finding/i)).toBeNull()
    await user.click(dialog.getByRole('radio', { name: /never/i }))
    expect(dialog.getByText(/one person can hide any finding/i)).toBeInTheDocument()
    expect(
      dialog.getByText(/a lower level takes effect 24 hours after you save/i)
    ).toBeInTheDocument()
    await user.click(dialog.getByRole('button', { name: 'Save' }))
    expect(update).toHaveBeenCalledWith({ fp_approval: 'off' })
  })

  it('choosing the level in force again saves it (a waiting lowering is replaced)', async () => {
    update.mockResolvedValue(settingsOf())
    render(
      <FindingApprovalsForm
        settings={settingsOf({
          pending_fp_approval: 'high_and_above',
          pending_fp_approval_at: '2026-10-16T12:00:00Z',
        })}
        canEdit
      />
    )
    const dialog = await openEditor(user, 'False positives')
    expect(dialog.getByRole('radio', { name: /only for serious findings/i })).toBeChecked()
    await user.click(dialog.getByRole('radio', { name: /always/i }))
    await user.click(dialog.getByRole('button', { name: 'Save' }))
    expect(update).toHaveBeenCalledWith({ fp_approval: 'all' })
  })

  it('keeps the second-look share within 0 to 10 and says a lower share waits', async () => {
    render(
      <FindingApprovalsForm
        settings={settingsOf({ fp_approval: 'off', second_look_percent: 5 })}
        canEdit
      />
    )
    const dialog = await openEditor(user, 'False positives')
    const input = dialog.getByLabelText(/second look/i)
    await user.clear(input)
    await user.type(input, '55')
    expect(input).toHaveValue(10)
    await user.clear(input)
    await user.type(input, '2')
    expect(dialog.getByText(/lower second-look share takes effect 24 hours/i)).toBeInTheDocument()
  })
})
