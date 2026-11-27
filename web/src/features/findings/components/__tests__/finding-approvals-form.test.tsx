import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { formatDateTime } from '@/lib/app-locale'
import { FindingApprovalsForm, editorSaveBody, savedMessage } from '../finding-approvals-form'
import { levelsFromSettings } from '../finding-approval-settings-form'
import { policyFromSettings } from '../approval-policy-form'
import { basePolicy, openEditor, settingsOf } from './approvals-test-setup'

const update = vi.fn()
vi.mock('../../api/use-findings-api', () => ({
  updateFindingApprovalSettings: (...args: unknown[]) => update(...args),
}))
const toastSuccess = vi.fn()
const toastError = vi.fn()
vi.mock('sonner', () => ({
  toast: {
    success: (...a: unknown[]) => toastSuccess(...a),
    error: (...a: unknown[]) => toastError(...a),
  },
}))
const groupsEnabled: boolean[] = []
vi.mock('@/features/access-control/api/use-groups', () => ({
  useGroups: (_f: unknown, enabled = true) => {
    groupsEnabled.push(enabled)
    return {
      groups: [{ id: '11111111-1111-1111-1111-111111111111', name: 'AppSec' }],
      isLoading: false,
    }
  },
}))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ can: () => true }),
  Permission: { GroupsRead: 'team:groups:read' },
}))

let user: ReturnType<typeof userEvent.setup>
beforeEach(() => {
  user = userEvent.setup({ delay: null })
  update.mockReset()
  toastSuccess.mockReset()
  toastError.mockReset()
  groupsEnabled.length = 0
})

describe('Settings > Approvals: one row per approval type', () => {
  it('says what is set in plain words, with no control and no save bar at rest', () => {
    render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    const row = (id: string) => document.getElementById(id) as HTMLElement
    expect(row('false-positives')).toHaveTextContent('A second person approves every one.')
    // Accepted risks follow the platform default per class.
    expect(row('accepted-risks')).toHaveTextContent(
      'Standard: Peer review; High: Security review; Critical: Two approvers.'
    )
    expect(row('suppression-rules')).toHaveTextContent(
      'False positive rules: Standard: Peer review'
    )
    expect(row('security-pool')).toHaveTextContent('No security pool.')
    expect(row('approval-limits')).toHaveTextContent('A request expires after 14 days.')
    expect(row('backup-contact')).toHaveTextContent('Not set')
    // Detail is on demand: no radio, select or field on the page itself.
    expect(screen.queryByRole('radio')).toBeNull()
    expect(screen.queryByRole('combobox')).toBeNull()
    expect(screen.queryByRole('textbox')).toBeNull()
    expect(screen.queryByRole('region', { name: 'Unsaved changes' })).toBeNull()
    // Every row's button has a name of its own.
    for (const name of [
      'Change False positives',
      'Change Accepted risks',
      'Change Suppression rules',
      'Change Approvers',
      'Change Deadline and high risk',
      'Change Backup contact',
    ])
      expect(screen.getByRole('button', { name })).toBeInTheDocument()
    // What the tiers mean stays folded.
    expect(screen.getByRole('button', { name: 'What the tiers mean' })).toHaveAttribute(
      'aria-expanded',
      'false'
    )
  })

  it('names the security pool only after reading the groups, and only when one is set', () => {
    const { unmount } = render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    expect(groupsEnabled.every((e) => !e)).toBe(true)
    unmount()
    groupsEnabled.length = 0
    render(
      <FindingApprovalsForm
        settings={settingsOf({
          policy: {
            ...basePolicy,
            security_pool_group_id: '11111111-1111-1111-1111-111111111111',
            security_pool_strict: true,
            exclude_assignee: true,
          },
        })}
        canEdit
      />
    )
    expect(groupsEnabled).toContain(true)
    expect(document.getElementById('security-pool')).toHaveTextContent(
      'Security pool: AppSec, nobody else. The assignee may not approve.'
    )
  })

  it('saves one editor with one request of only what it changed, then closes', async () => {
    const next = settingsOf({ backup_contact_email: 'advisor@example.com' })
    update.mockResolvedValue(next)
    const onSaved = vi.fn()
    render(<FindingApprovalsForm settings={settingsOf()} canEdit onSaved={onSaved} />)
    const dialog = await openEditor(user, 'Backup contact')
    await user.type(dialog.getByLabelText(/email address/i), 'advisor@example.com')
    await user.click(dialog.getByRole('button', { name: 'Save' }))
    expect(update).toHaveBeenCalledTimes(1)
    expect(update).toHaveBeenCalledWith({ backup_contact_email: 'advisor@example.com' })
    expect(onSaved).toHaveBeenCalledWith(next)
    expect(toastSuccess).toHaveBeenCalledWith('Finding approval settings saved')
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('closes without a request when nothing changed', async () => {
    render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    const dialog = await openEditor(user, 'Approvers')
    await user.click(dialog.getByRole('button', { name: 'Save' }))
    expect(update).not.toHaveBeenCalled()
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('keeps the draft and says why when the save is refused (a lowering by an administrator)', async () => {
    update.mockRejectedValue(new Error('Only an owner can lower the approval level'))
    render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    const dialog = await openEditor(user, 'False positives')
    await user.click(dialog.getByRole('radio', { name: /never/i }))
    await user.click(dialog.getByRole('button', { name: 'Save' }))
    expect(update).toHaveBeenCalledWith({ fp_approval: 'off' })
    expect(await dialog.findByTestId('form-dialog-error')).toHaveTextContent(
      'Only an owner can lower the approval level'
    )
    expect(dialog.getByRole('radio', { name: /never/i })).toBeChecked()
  })

  it('opens each editor from the saved values, never from an earlier draft', async () => {
    render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    let dialog = await openEditor(user, 'False positives')
    await user.click(dialog.getByRole('radio', { name: /never/i }))
    await user.keyboard('{Escape}')
    // Closing with changes asks first; discard them.
    await user.click(await screen.findByRole('button', { name: /discard/i }))
    dialog = await openEditor(user, 'False positives')
    expect(dialog.getByRole('radio', { name: /always/i })).toBeChecked()
  })

  it('is view only without settings:write: View opens the editor with nothing to save', async () => {
    render(<FindingApprovalsForm settings={settingsOf()} canEdit={false} />)
    expect(screen.queryByRole('button', { name: /^Change/ })).toBeNull()
    const dialog = await openEditor(user, 'Accepted risks', 'View')
    for (const r of dialog.getAllByRole('radio')) expect(r).toBeDisabled()
    expect(dialog.queryByRole('button', { name: 'Save' })).toBeNull()
    // Closed by its X or the footer's Close; nothing to save.
    expect(dialog.getAllByRole('button', { name: 'Close' })).toHaveLength(2)
  })
})

describe('Settings > Approvals: lowered protections waiting', () => {
  const waiting = settingsOf({
    fp_approval: 'all',
    pending_fp_approval: 'off',
    pending_fp_approval_at: '2026-10-16T12:00:00Z',
    second_look_percent: 5,
    pending_second_look_percent: 0,
    pending_second_look_at: '2026-10-16T12:00:00Z',
    policy: { ...basePolicy, exclude_assignee: true },
    pending_policy: basePolicy,
    pending_policy_at: '2026-10-17T10:00:00Z',
  })

  it('lists each waiting change with its time, above the rows', () => {
    render(<FindingApprovalsForm settings={waiting} canEdit />)
    const notice = within(screen.getByTestId('approval-policy-pending'))
    expect(notice.getByText('Lower protections are waiting')).toBeInTheDocument()
    expect(notice.getByText(/until then the stricter settings apply/i)).toBeInTheDocument()
    expect(
      notice.getByText(
        `False positives: "Never" from ${formatDateTime(new Date('2026-10-16T12:00:00Z'))}`
      )
    ).toBeInTheDocument()
    expect(notice.getByText(/^Second look: 0 % from/)).toBeInTheDocument()
    expect(
      notice.getByText(
        `Relaxed approval rules from ${formatDateTime(new Date('2026-10-17T10:00:00Z'))}`
      )
    ).toBeInTheDocument()
    // The row says it waits too, and summarises the chosen (lower) level.
    expect(document.getElementById('false-positives')).toHaveTextContent('One person decides.')
    expect(document.getElementById('false-positives')).toHaveTextContent(
      'A lower setting takes effect at'
    )
  })

  it('cancels every waiting change with the explicit cancel_pending flag', async () => {
    update.mockResolvedValue(settingsOf())
    const onSaved = vi.fn()
    render(<FindingApprovalsForm settings={waiting} canEdit onSaved={onSaved} />)
    await user.click(screen.getByRole('button', { name: 'Cancel the waiting changes' }))
    expect(update).toHaveBeenCalledWith({ cancel_pending: true })
    expect(onSaved).toHaveBeenCalled()
  })

  it('hides the cancel button without settings:write', () => {
    render(<FindingApprovalsForm settings={waiting} canEdit={false} />)
    expect(screen.getByTestId('approval-policy-pending')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /cancel the waiting/i })).toBeNull()
  })
})

describe('editorSaveBody and savedMessage', () => {
  const t = (_k: string, d: string) => d
  it('sends nothing when nothing changed, the changed level alone, or the whole policy', () => {
    const s = settingsOf()
    const levels = levelsFromSettings(s)
    const policy = policyFromSettings(s)
    expect(editorSaveBody(levels, policy, s)).toBeNull()
    expect(editorSaveBody({ ...levels, acceptLevel: 'off' }, policy, s)).toEqual({
      accept_approval: 'off',
    })
    const body = editorSaveBody(levels, { ...policy, stepUpAll: true }, s)
    expect(Object.keys(body ?? {})).toEqual(['policy'])
    expect(body?.policy).toMatchObject({ step_up_all_tiers: true, tiers: {} })
  })

  it('says when a lowering or a relaxation waits 24 hours', () => {
    const s = settingsOf()
    expect(
      savedMessage(t as never, { fp_approval: 'off' }, s, { ...s, pending_fp_approval: 'off' })
    ).toMatch(/lower level takes effect in 24 hours/)
    expect(
      savedMessage(t as never, { policy: { ...basePolicy } }, s, {
        ...s,
        pending_policy_at: '2026-10-17T10:00:00Z',
      })
    ).toMatch(/relaxed rules take effect in 24 hours/)
    expect(savedMessage(t as never, { fp_approval: 'all' }, s, s)).toBe(
      'Finding approval settings saved'
    )
  })
})
