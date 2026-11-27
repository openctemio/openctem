/**
 * Shared by the Settings > Approvals tests: the platform tables
 * (server/pkg/domain/approvalpolicy/tier.go), settings fixtures and the
 * editor opener. The mocks stay in each test file (vi.mock is hoisted there).
 */
import { screen, within } from '@testing-library/react'
import type userEvent from '@testing-library/user-event'
import type { FindingApprovalSettings } from '../../api/use-findings-api'

if (!('ResizeObserver' in globalThis)) {
  ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}
if (!Element.prototype.scrollIntoView) Element.prototype.scrollIntoView = () => {}
if (!Element.prototype.hasPointerCapture) Element.prototype.hasPointerCapture = () => false

export const floors: Record<string, string> = {
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
export const defaults: Record<string, string> = {
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

export const basePolicy = {
  security_pool_strict: false,
  exclude_assignee: false,
  step_up_all_tiers: false,
  on_material_change_accepted: 'end_on_tier_rise' as const,
  on_material_change_single_person_fp: 'flag' as const,
}

export function settingsOf(over: Partial<FindingApprovalSettings> = {}): FindingApprovalSettings {
  return {
    backup_contact_email: '',
    fp_approval: 'all',
    accept_approval: 'all',
    second_look_percent: 0,
    policy: basePolicy,
    floors,
    defaults,
    ...over,
  }
}

type User = ReturnType<typeof userEvent.setup>

/** Opens a row's editor ("Change False positives") and returns the dialog. */
export async function openEditor(user: User, row: string, action = 'Change') {
  await user.click(screen.getByRole('button', { name: `${action} ${row}` }))
  return within(await screen.findByRole('dialog', { name: row }))
}

/** The options a tier cell offers. */
export async function optionsOf(user: User, cell: string): Promise<string[]> {
  await user.click(screen.getByTestId(`tier-${cell}`))
  const listbox = await screen.findByRole('listbox')
  const names = within(listbox)
    .getAllByRole('option')
    .map((o) => o.textContent ?? '')
  await user.keyboard('{Escape}')
  return names
}
