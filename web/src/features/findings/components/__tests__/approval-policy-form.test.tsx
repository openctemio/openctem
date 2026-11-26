import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FindingApprovalsForm } from '../finding-approvals-form'
import { basePolicy, openEditor, optionsOf, settingsOf } from './approvals-test-setup'

const update = vi.fn()
vi.mock('../../api/use-findings-api', () => ({
  updateFindingApprovalSettings: (...args: unknown[]) => update(...args),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/features/access-control/api/use-groups', () => ({
  useGroups: () => ({
    groups: [{ id: '11111111-1111-1111-1111-111111111111', name: 'AppSec' }],
    isLoading: false,
  }),
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

describe('Approvals editors: who approves, by risk', () => {
  it('never offers a tier below the floor', async () => {
    render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    await openEditor(user, 'Accepted risks')
    // accepted.critical: floor security, default dual.
    const critical = await optionsOf(user, 'accepted.critical')
    expect(critical).toEqual(['Default: Two approvers', 'Security review'])
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    // A rule never decides alone: no "One person" anywhere in a rule row.
    await openEditor(user, 'Suppression rules')
    for (const cls of ['standard', 'high', 'critical']) {
      expect(await optionsOf(user, `rule_false_positive.${cls}`)).not.toContain('One person')
      expect(await optionsOf(user, `rule_accepted.${cls}`)).not.toContain('One person')
    }
  }, 30_000)

  it('shows the floor and marks a cell equal to the default as Default', async () => {
    render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    const dialog = await openEditor(user, 'Accepted risks')
    expect(dialog.getByTestId('tier-accepted.high')).toHaveTextContent(/^Security review$/)
    expect(dialog.getAllByText('Default, minimum: Security review').length).toBeGreaterThan(0)
  })

  it('saves the whole policy with only the cells that differ from the default', async () => {
    update.mockResolvedValue(settingsOf())
    render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    const dialog = await openEditor(user, 'Accepted risks')
    await user.click(dialog.getByTestId('tier-accepted.high'))
    await user.click(await screen.findByRole('option', { name: 'Two approvers' }))
    await user.click(dialog.getByRole('button', { name: 'Save' }))
    expect(update).toHaveBeenCalledTimes(1)
    const body = update.mock.calls[0][0] as { policy: Record<string, unknown> }
    // Only the policy changed: the body is the policy alone.
    expect(Object.keys(body)).toEqual(['policy'])
    expect(body.policy.tiers).toEqual({ 'accepted.high': 'dual' })
    expect(body.policy).toMatchObject({
      security_pool_strict: false,
      exclude_assignee: false,
      step_up_all_tiers: false,
      on_material_change_accepted: 'end_on_tier_rise',
    })
  })

  it('raises a false positive tier from its own editor', async () => {
    update.mockResolvedValue(settingsOf())
    render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    const dialog = await openEditor(user, 'False positives')
    // A false-positive cell only raises the level: no "One person".
    expect(await optionsOf(user, 'false_positive.critical')).not.toContain('One person')
    await user.click(dialog.getByTestId('tier-false_positive.critical'))
    await user.click(await screen.findByRole('option', { name: 'Two approvers' }))
    await user.click(dialog.getByRole('button', { name: 'Save' }))
    const body = update.mock.calls[0][0] as { policy: { tiers: Record<string, string> } }
    expect(body.policy.tiers).toEqual({ 'false_positive.critical': 'dual' })
  })

  it('refuses an acceptance cap above the platform maximum', async () => {
    render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    const dialog = await openEditor(user, 'Accepted risks')
    const [standard] = dialog.getAllByLabelText('Standard', { selector: 'input' })
    await user.type(standard, '400')
    expect(dialog.getByRole('alert')).toHaveTextContent('Enter whole days from 1 to 365.')
    expect(dialog.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('refuses a decision deadline outside 1 to 14 days', async () => {
    render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    const dialog = await openEditor(user, 'Deadline and high risk')
    await user.type(dialog.getByLabelText(/decision deadline/i), '30')
    expect(dialog.getByRole('button', { name: 'Save' })).toBeDisabled()
  })
})

describe('Approvals editors: approvers', () => {
  it('needs a security pool before the strict toggle can be set', async () => {
    render(<FindingApprovalsForm settings={settingsOf()} canEdit />)
    const dialog = await openEditor(user, 'Approvers')
    expect(dialog.getByRole('switch', { name: /only the security reviewer group/i })).toBeDisabled()
  })

  it('starts from the waiting relaxed policy', async () => {
    render(
      <FindingApprovalsForm
        settings={settingsOf({
          policy: { ...basePolicy, exclude_assignee: true },
          pending_policy: basePolicy,
          pending_policy_at: '2026-10-17T10:00:00Z',
        })}
        canEdit
      />
    )
    const dialog = await openEditor(user, 'Approvers')
    expect(dialog.getByRole('switch', { name: /exclude the assignee/i })).not.toBeChecked()
  })

  it('is read-only without settings:write', async () => {
    render(<FindingApprovalsForm settings={settingsOf()} canEdit={false} />)
    let dialog = await openEditor(user, 'Approvers', 'View')
    expect(dialog.getByRole('switch', { name: /exclude the assignee/i })).toBeDisabled()
    await user.click(dialog.getAllByRole('button', { name: 'Close' })[0])
    dialog = await openEditor(user, 'Accepted risks', 'View')
    expect(dialog.getByTestId('tier-accepted.high')).toBeDisabled()
  })
})
