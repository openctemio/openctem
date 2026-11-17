import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FindingApprovalsForm } from '../finding-approvals-form'
import type { FindingApprovalSettings } from '../../api/use-findings-api'

if (!('ResizeObserver' in globalThis)) {
  ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}
if (!Element.prototype.scrollIntoView) Element.prototype.scrollIntoView = () => {}

const update = vi.fn()
vi.mock('../../api/use-findings-api', () => ({
  updateFindingApprovalSettings: (...args: unknown[]) => update(...args),
}))
const toastError = vi.fn()
vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: (...a: unknown[]) => toastError(...a) },
}))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useGroups: () => ({ groups: [], isLoading: false }),
}))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ can: () => true }),
  Permission: { GroupsRead: 'team:groups:read' },
}))

const policy = {
  security_pool_strict: false,
  exclude_assignee: false,
  step_up_all_tiers: false,
  on_material_change_accepted: 'end_on_tier_rise' as const,
  on_material_change_single_person_fp: 'flag' as const,
}
const saved: FindingApprovalSettings = {
  backup_contact_email: '',
  fp_approval: 'all',
  accept_approval: 'all',
  second_look_percent: 0,
  policy,
}
const fpGroup = () => within(screen.getByRole('group', { name: /false positive/i }))

describe('FindingApprovalsForm: one save bar for every finding approval setting', () => {
  beforeEach(() => {
    update.mockReset()
    toastError.mockReset()
  })

  it('sends one request whose body is the union of what each part sent alone', async () => {
    update.mockResolvedValue(saved)
    render(<FindingApprovalsForm settings={saved} canEdit />)
    await userEvent.click(fpGroup().getByRole('radio', { name: /only for serious findings/i }))
    await userEvent.click(screen.getByRole('switch', { name: /exclude the assignee/i }))
    await userEvent.type(screen.getByLabelText(/backup contact/i), 'advisor@example.com')
    // One bar counts every change of both parts.
    expect(screen.getByText('3 unsaved changes')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /save changes/i }))
    expect(update).toHaveBeenCalledTimes(1)
    const body = update.mock.calls[0][0] as Record<string, unknown>
    expect(Object.keys(body).sort()).toEqual(['backup_contact_email', 'fp_approval', 'policy'])
    expect(body).toMatchObject({
      backup_contact_email: 'advisor@example.com',
      fp_approval: 'high_and_above',
      policy: { exclude_assignee: true, tiers: {} },
    })
  })

  it('keeps the draft and says so when the save fails', async () => {
    update.mockRejectedValue(new Error('refused'))
    render(<FindingApprovalsForm settings={saved} canEdit />)
    await userEvent.click(screen.getByRole('switch', { name: /exclude the assignee/i }))
    await userEvent.click(screen.getByRole('button', { name: /save changes/i }))
    expect(await screen.findByText("Couldn't save. Your changes are kept.")).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: /exclude the assignee/i })).toBeChecked()
    expect(toastError).toHaveBeenCalled()
  })

  it('takes the saved values after a save', async () => {
    const next = { ...saved, policy: { ...policy, exclude_assignee: true } }
    update.mockResolvedValue(next)
    const { rerender } = render(<FindingApprovalsForm settings={saved} canEdit />)
    await userEvent.click(screen.getByRole('switch', { name: /exclude the assignee/i }))
    await userEvent.click(screen.getByRole('button', { name: /save changes/i }))
    rerender(<FindingApprovalsForm settings={next} canEdit />)
    expect(screen.queryByRole('region', { name: 'Unsaved changes' })).toBeNull()
    expect(screen.getByRole('switch', { name: /exclude the assignee/i })).toBeChecked()
  })
})
