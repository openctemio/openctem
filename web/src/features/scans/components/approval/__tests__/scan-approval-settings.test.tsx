/**
 * Settings > Scan approval on the settings page pattern. The mode radios
 * show the mode in force: when the platform enforces a mode over the
 * organization's choice, that mode is the selected one (read-only) and the
 * organization's own choice is a note. An owner's mode change is saved
 * through the page's save bar, after a reason; rule changes apply one by
 * one, each after a reason. View only without owner or administrator.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { I18nProvider } from '@/context/i18n-provider'

const gov = vi.hoisted(() => ({
  data: null as unknown,
  error: undefined as unknown,
  isLoading: false,
  mutate: vi.fn(),
  saveMode: vi.fn(),
  saveRules: vi.fn(),
}))
const perms = vi.hoisted(() => ({ owner: true, admin: true }))
vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))
vi.mock('@/lib/api/scan-approval-hooks', () => ({
  useScanGovernance: () => ({
    data: gov.data,
    error: gov.error,
    isLoading: gov.isLoading,
    mutate: gov.mutate,
  }),
  saveScanGovernanceMode: gov.saveMode,
  saveScanGovernanceRules: gov.saveRules,
}))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ isOwner: () => perms.owner, isAdmin: () => perms.admin }),
}))
vi.mock('../approval-rule-tester', () => ({
  ApprovalRuleTester: () => <p>rule tester</p>,
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const { ScanApprovalSettings } = await import('../scan-approval-settings')

const RULE = {
  id: 'r1',
  name: 'Production hosts from the internet, Kho dữ liệu khách hàng miền Nam',
  enabled: true,
  monitor: false,
  conditions: { min_intensity: 'intrusive' as const, crown_jewel: true },
  requirement: { approvals: 2, require_justification: true },
}
const base = {
  rules: [] as unknown[],
  selectable_modes: ['off', 'on', 'strict'],
  pending_expiry_days: 7,
  presets: { light: [], standard: [RULE], strict: [RULE] },
}

function open(locale: 'en' | 'vi' = 'en') {
  return render(
    <I18nProvider locale={locale}>
      <ScanApprovalSettings />
    </I18nProvider>
  )
}

describe('ScanApprovalSettings', () => {
  beforeEach(() => {
    perms.owner = true
    perms.admin = true
    gov.error = undefined
    gov.isLoading = false
    gov.mutate.mockReset()
    gov.saveMode.mockReset()
    gov.saveMode.mockResolvedValue(undefined)
    gov.saveRules.mockReset()
    gov.saveRules.mockResolvedValue(undefined)
    gov.data = { ...base, mode: 'off', organization_mode: 'off', source: 'organization' }
  })

  it('draws the mode and the rules as two framed sections, no Save button at rest', () => {
    open()
    expect(screen.getByRole('heading', { level: 1, name: 'Scan approval' })).toBeVisible()
    const headings = screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)
    expect(headings).toEqual(['Mode', 'Approval rules'])
    expect(screen.getByText('In force: Off.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Save/ })).toBeNull()
    expect(screen.getByText(/No rules: no scan needs approval/)).toBeInTheDocument()
    expect(document.getElementById('mode')).not.toBeNull()
    expect(document.getElementById('rules')).not.toBeNull()
  })

  it('shows the enforced mode selected and the organization choice as a note', () => {
    gov.data = { ...base, mode: 'strict', organization_mode: 'off', source: 'platform' }
    open()
    expect(screen.getByRole('radio', { name: /Strict/ })).toBeChecked()
    expect(screen.getByRole('radio', { name: /Off/ })).not.toBeChecked()
    expect(screen.getByRole('radio', { name: /Off/ })).toBeDisabled()
    expect(screen.getByText(/Your organization chose Off/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Save changes/ })).toBeNull()
  })

  it('without enforcement the radios show the organization choice, editable by an owner', () => {
    gov.data = { ...base, mode: 'on', organization_mode: 'on', source: 'organization' }
    open()
    expect(screen.getByRole('radio', { name: /^On/ })).toBeChecked()
    expect(screen.getByRole('radio', { name: /^On/ })).toBeEnabled()
    expect(screen.queryByText(/Your organization chose/)).toBeNull()
  })

  it('an owner changes the mode through the save bar, with a reason', async () => {
    const user = userEvent.setup()
    open()
    await user.click(screen.getByRole('radio', { name: /^On/ }))
    const bar = screen.getByRole('region', { name: 'Unsaved changes' })
    expect(bar).toHaveTextContent('1 unsaved change')
    await user.click(within(bar).getByRole('button', { name: /Save changes/ }))
    const dialog = screen.getByRole('dialog', { name: 'Change scan approval?' })
    expect(dialog).toHaveTextContent('New mode: On.')
    const confirm = within(dialog).getByRole('button', { name: 'Confirm' })
    expect(confirm).toBeDisabled()
    await user.type(within(dialog).getByLabelText('Reason'), 'Quét môi trường sản xuất')
    await user.click(confirm)
    expect(gov.saveMode).toHaveBeenCalledWith('on', 'Quét môi trường sản xuất')
    expect(gov.mutate).toHaveBeenCalled()
  })

  it('Discard puts the saved mode back', async () => {
    const user = userEvent.setup()
    open()
    await user.click(screen.getByRole('radio', { name: /Strict/ }))
    await user.click(screen.getByRole('button', { name: 'Discard' }))
    expect(screen.getByRole('radio', { name: /Off/ })).toBeChecked()
    expect(screen.queryByRole('region', { name: 'Unsaved changes' })).toBeNull()
  })

  it('an administrator edits the rules but not the mode', () => {
    perms.owner = false
    open()
    expect(screen.getByRole('radio', { name: /^On/ })).toBeDisabled()
    expect(screen.getByText('Only an owner changes the mode.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add rule' })).toBeEnabled()
    expect(screen.queryByText(/View only/)).toBeNull()
  })

  it('a preset replaces the rules after a reason, applied at once', async () => {
    const user = userEvent.setup()
    open()
    await user.click(screen.getByRole('button', { name: 'Standard' }))
    const dialog = screen.getByRole('dialog', { name: 'Change scan approval?' })
    expect(dialog).toHaveTextContent('Replace the rules with the Standard preset')
    await user.type(within(dialog).getByLabelText('Reason'), 'baseline')
    await user.click(within(dialog).getByRole('button', { name: 'Confirm' }))
    expect(gov.saveRules).toHaveBeenCalledWith([RULE], 7, 'baseline')
  })

  it('lists rules with long names and offers the rule tester', async () => {
    gov.data = {
      ...base,
      rules: [RULE],
      mode: 'on',
      organization_mode: 'on',
      source: 'organization',
    }
    const user = userEvent.setup()
    open()
    expect(screen.getByText(RULE.name)).toBeInTheDocument()
    const tryIt = screen.getByRole('button', { name: 'Try the rules on existing scans' })
    expect(tryIt).toHaveAttribute('aria-expanded', 'false')
    await user.click(tryIt)
    expect(screen.getByText('rule tester')).toBeInTheDocument()
  })

  it('is view only without owner or administrator', () => {
    perms.owner = false
    perms.admin = false
    open()
    expect(
      screen.getByText('View only. Only owners and administrators can change these settings.')
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Add rule' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Standard' })).toBeNull()
  })

  it('shows loading, then a load failure with Retry', async () => {
    gov.data = null
    gov.isLoading = true
    const { unmount } = open()
    expect(screen.getByLabelText('Loading Scan approval')).toBeInTheDocument()
    unmount()
    gov.isLoading = false
    gov.error = new Error('down')
    open()
    expect(screen.getByText("Couldn't load Scan approval")).toBeInTheDocument()
    await userEvent.setup().click(screen.getByRole('button', { name: 'Retry' }))
    expect(gov.mutate).toHaveBeenCalled()
  })

  it('renders the Vietnamese catalog', () => {
    open('vi')
    const headings = screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)
    expect(headings[0]).toBe('Chế độ')
  })
})
