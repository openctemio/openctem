import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ApprovalPolicyForm } from '../approval-policy-form'
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

// The platform tables of RFC-111 §3.1.
const floors: Record<string, string> = {
  'false_positive.standard': 'single',
  'false_positive.high': 'single',
  'false_positive.critical': 'single',
  'accepted.standard': 'peer',
  'accepted.high': 'security',
  'accepted.critical': 'security',
  'rule_false_positive.standard': 'peer',
  'rule_false_positive.high': 'peer',
  'rule_false_positive.critical': 'peer',
  'rule_accepted.standard': 'peer',
  'rule_accepted.high': 'security',
  'rule_accepted.critical': 'security',
}
const defaults: Record<string, string> = {
  'false_positive.standard': 'peer',
  'false_positive.high': 'peer',
  'false_positive.critical': 'peer',
  'accepted.standard': 'peer',
  'accepted.high': 'security',
  'accepted.critical': 'dual',
  'rule_false_positive.standard': 'peer',
  'rule_false_positive.high': 'security',
  'rule_false_positive.critical': 'security',
  'rule_accepted.standard': 'peer',
  'rule_accepted.high': 'security',
  'rule_accepted.critical': 'dual',
}

const basePolicy = {
  security_pool_strict: false,
  exclude_assignee: false,
  step_up_all_tiers: false,
  on_material_change_accepted: 'end_on_tier_rise' as const,
  on_material_change_single_person_fp: 'flag' as const,
}

function settings(over: Partial<FindingApprovalSettings> = {}): FindingApprovalSettings {
  return { backup_contact_email: '', policy: basePolicy, floors, defaults, ...over }
}

async function optionsOf(cell: string): Promise<string[]> {
  await userEvent.click(screen.getByTestId(`tier-${cell}`))
  const listbox = await screen.findByRole('listbox')
  const names = within(listbox)
    .getAllByRole('option')
    .map((o) => o.textContent ?? '')
  await userEvent.keyboard('{Escape}')
  return names
}

describe('ApprovalPolicyForm — tier grid', () => {
  beforeEach(() => update.mockReset())

  it('never offers a tier below the floor', async () => {
    render(<ApprovalPolicyForm settings={settings()} canEdit />)
    // accepted.critical: floor security, default dual.
    const critical = await optionsOf('accepted.critical')
    expect(critical).toEqual(['Default (Two approvers)', 'Security review'])
    expect(critical).not.toContain('One person')
    expect(critical).not.toContain('Peer review')
    // A rule never decides alone: no "One person" anywhere in a rule row.
    for (const cls of ['standard', 'high', 'critical']) {
      expect(await optionsOf(`rule_false_positive.${cls}`)).not.toContain('One person')
    }
  })

  it('shows the floor and marks a cell equal to the default as Default', () => {
    render(<ApprovalPolicyForm settings={settings()} canEdit />)
    expect(screen.getByTestId('tier-accepted.high')).toHaveTextContent('Default (Security review)')
    expect(screen.getAllByText('Minimum: Security review').length).toBeGreaterThan(0)
  })

  it('saves the whole policy with only the cells that differ from the default', async () => {
    update.mockResolvedValue(settings())
    render(<ApprovalPolicyForm settings={settings()} canEdit />)
    const save = screen.getByRole('button', { name: /save approval policy/i })
    expect(save).toBeDisabled()
    await userEvent.click(screen.getByTestId('tier-accepted.high'))
    await userEvent.click(await screen.findByRole('option', { name: 'Two approvers' }))
    await userEvent.click(save)
    expect(update).toHaveBeenCalledTimes(1)
    const body = update.mock.calls[0][0] as { policy: Record<string, unknown> }
    expect(body.policy.tiers).toEqual({ 'accepted.high': 'dual' })
    expect(body.policy).toMatchObject({
      security_pool_strict: false,
      exclude_assignee: false,
      step_up_all_tiers: false,
      on_material_change_accepted: 'end_on_tier_rise',
    })
  })

  it('refuses an acceptance cap above the platform maximum', async () => {
    render(<ApprovalPolicyForm settings={settings()} canEdit />)
    const [standard] = screen.getAllByLabelText('Standard', { selector: 'input' })
    await userEvent.type(standard, '400')
    expect(screen.getByRole('alert')).toHaveTextContent('Enter whole days from 1 to 365.')
    expect(screen.getByRole('button', { name: /save approval policy/i })).toBeDisabled()
  })

  it('needs a security pool before the strict toggle can be set', () => {
    render(<ApprovalPolicyForm settings={settings()} canEdit />)
    expect(screen.getByRole('switch', { name: /only the security pool/i })).toBeDisabled()
  })
})

describe('ApprovalPolicyForm — relaxation', () => {
  beforeEach(() => update.mockReset())

  it('shows the waiting relaxation with its time and edits the chosen policy', () => {
    render(
      <ApprovalPolicyForm
        settings={settings({
          policy: { ...basePolicy, exclude_assignee: true },
          pending_policy: basePolicy,
          pending_policy_at: '2026-10-17T10:00:00Z',
        })}
        canEdit
      />
    )
    const banner = screen.getByTestId('approval-policy-pending')
    expect(banner).toHaveTextContent('A relaxed approval policy is waiting')
    expect(banner).toHaveTextContent(new Date('2026-10-17T10:00:00Z').toLocaleString())
    expect(banner).toHaveTextContent('the stricter rules')
    // The editor starts from the last chosen (pending) policy.
    expect(screen.getByRole('switch', { name: /exclude the assignee/i })).not.toBeChecked()
  })

  it('cancels a waiting relaxation by saving the policy in force', async () => {
    const inForce = { ...basePolicy, exclude_assignee: true }
    update.mockResolvedValue(settings({ policy: inForce }))
    render(
      <ApprovalPolicyForm
        settings={settings({
          policy: inForce,
          pending_policy: basePolicy,
          pending_policy_at: '2026-10-17T10:00:00Z',
        })}
        canEdit
      />
    )
    await userEvent.click(screen.getByRole('button', { name: /cancel the change/i }))
    expect(update).toHaveBeenCalledWith({ policy: inForce })
  })

  it('is read-only without settings:write', () => {
    render(<ApprovalPolicyForm settings={settings()} canEdit={false} />)
    expect(screen.getByTestId('tier-accepted.high')).toBeDisabled()
    expect(screen.getByRole('switch', { name: /exclude the assignee/i })).toBeDisabled()
    expect(screen.queryByRole('button', { name: /save approval policy/i })).not.toBeInTheDocument()
  })
})
