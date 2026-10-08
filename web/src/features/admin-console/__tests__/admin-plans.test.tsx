import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { PlanDefaultsResponse, PlanSummaryResponse } from '@/lib/api/generated'
import { AdminApiError } from '../api/admin-client'
import {
  deletePlanOverride,
  putPlanOverride,
  savePlanDefaults,
  setTenantPlan,
  useTenantPlan,
} from '../api/use-plans'
import { parseLimit, PlanDefaultsForm } from '../components/plan-defaults-form'
import { OrganizationPlanPanel } from '../components/organization-plan-panel'

vi.mock('../api/use-plans', async (orig) => ({
  ...(await orig<typeof import('../api/use-plans')>()),
  savePlanDefaults: vi.fn(),
  useTenantPlan: vi.fn(),
  setTenantPlan: vi.fn(),
  putPlanOverride: vi.fn(),
  deletePlanOverride: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const BUILTIN: PlanDefaultsResponse = {
  builtin: true,
  version: 0,
  keys: ['seats', 'assets'],
  plans: {
    free: { seats: 5, assets: 500, sensors: 2, api_keys: 5, ci_trusts: 2, invites_per_day: 20 },
    pro: { seats: -1 },
    enterprise: {},
  },
}

describe('parseLimit', () => {
  it('empty is unlimited, digits are a limit, anything else is invalid', () => {
    expect(parseLimit('')).toBe(-1)
    expect(parseLimit('  ')).toBe(-1)
    expect(parseLimit('0')).toBe(0)
    expect(parseLimit('25')).toBe(25)
    expect(parseLimit('-1')).toBeNull()
    expect(parseLimit('2.5')).toBeNull()
    expect(parseLimit('ten')).toBeNull()
    expect(parseLimit('99999999999999999999')).toBeNull()
  })
})

describe('PlanDefaultsForm', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows the built-in limits; empty means unlimited', () => {
    render(<PlanDefaultsForm defaults={BUILTIN} canEdit onSaved={vi.fn()} />)
    expect(screen.getByLabelText('Free: Seats')).toHaveValue('5')
    expect(screen.getByLabelText('Pro: Seats')).toHaveValue('')
    expect(screen.getByText(/built-in defaults apply/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('a read-only administrator cannot change them', () => {
    render(<PlanDefaultsForm defaults={BUILTIN} canEdit={false} onSaved={vi.fn()} />)
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('Free: Seats')).toBeDisabled()
  })

  it('refuses a value that is not a whole number', async () => {
    const user = userEvent.setup()
    render(<PlanDefaultsForm defaults={BUILTIN} canEdit onSaved={vi.fn()} />)
    await user.clear(screen.getByLabelText('Free: Seats'))
    await user.type(screen.getByLabelText('Free: Seats'), '-3')
    expect(screen.getByText(/whole number of 0 or more/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('saves every plan with the authenticator code and the version read', async () => {
    const user = userEvent.setup()
    const onSaved = vi.fn()
    vi.mocked(savePlanDefaults).mockResolvedValue({ ...BUILTIN, version: 1, builtin: false })
    render(<PlanDefaultsForm defaults={BUILTIN} canEdit onSaved={onSaved} />)
    await user.clear(screen.getByLabelText('Free: Seats'))
    await user.type(screen.getByLabelText('Free: Seats'), '3')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    const confirm = screen.getByRole('button', { name: 'Confirm' })
    expect(confirm).toBeDisabled()
    await user.type(screen.getByLabelText(/code from your authenticator/i), '123456')
    await user.click(confirm)

    await waitFor(() => expect(savePlanDefaults).toHaveBeenCalled())
    const arg = vi.mocked(savePlanDefaults).mock.calls[0][0]
    expect(arg.version).toBe(0)
    expect(arg.totp_code).toBe('123456')
    expect(arg.plans?.free?.seats).toBe(3)
    expect(arg.plans?.free?.platform_scans_per_day).toBe(-1)
    expect(arg.plans?.pro?.seats).toBe(-1)
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
  })

  it('a wrong code keeps the dialog open with the reason', async () => {
    const user = userEvent.setup()
    vi.mocked(savePlanDefaults).mockRejectedValue(
      new AdminApiError('Invalid or already used code', 401)
    )
    render(<PlanDefaultsForm defaults={BUILTIN} canEdit onSaved={vi.fn()} />)
    await user.type(screen.getByLabelText('Pro: Assets'), '1000')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await user.type(screen.getByLabelText(/code from your authenticator/i), '000000')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByText('Invalid or already used code')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument()
  })
})

const OVER: PlanSummaryResponse = {
  plan: 'free',
  over_limit: true,
  limits: [
    { key: 'seats', limit: 5, used: 7, source: 'plan', over_limit: true },
    { key: 'assets', limit: 1000, used: 20, source: 'override', override_reason: 'pilot' },
    { key: 'sensors', limit: -1, used: 3, source: 'plan' },
  ],
}

function mockPlan(data: PlanSummaryResponse) {
  const mutate = vi.fn()
  vi.mocked(useTenantPlan).mockReturnValue({
    data,
    error: undefined,
    isLoading: false,
    isValidating: false,
    mutate,
  } as unknown as ReturnType<typeof useTenantPlan>)
  return mutate
}

describe('OrganizationPlanPanel', () => {
  beforeEach(() => vi.clearAllMocks())

  it('flags an organization over its limits without hiding anything', () => {
    mockPlan(OVER)
    render(<OrganizationPlanPanel tenantId="t1" canManage />)
    expect(screen.getAllByText('Over limit').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(screen.getByText(/set for this organization: pilot/i)).toBeInTheDocument()
    expect(screen.getAllByText('Unlimited').length).toBeGreaterThan(0)
  })

  it('a read-only administrator sees the plan but cannot change it', () => {
    mockPlan(OVER)
    render(<OrganizationPlanPanel tenantId="t1" canManage={false} />)
    expect(screen.getByRole('combobox', { name: 'Plan' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: /set the seats limit/i })).not.toBeInTheDocument()
    expect(screen.getByText(/needs an operations admin/i)).toBeInTheDocument()
  })

  it('an override needs a reason before it can be saved', async () => {
    const user = userEvent.setup()
    mockPlan(OVER)
    vi.mocked(putPlanOverride).mockResolvedValue(OVER)
    render(<OrganizationPlanPanel tenantId="t1" canManage />)
    await user.click(screen.getByRole('button', { name: /set the seats limit/i }))
    const save = screen.getByRole('button', { name: 'Save' })
    await user.clear(screen.getByLabelText('Limit'))
    await user.type(screen.getByLabelText('Limit'), '10')
    expect(save).toBeDisabled()
    await user.type(screen.getByLabelText('Reason'), 'pilot extension')
    expect(save).toBeEnabled()
    await user.click(save)
    await waitFor(() =>
      expect(putPlanOverride).toHaveBeenCalledWith('t1', 'seats', {
        value: 10,
        reason: 'pilot extension',
        expires_at: undefined,
      })
    )
  })

  it('removing an override goes back to the plan limit', async () => {
    const user = userEvent.setup()
    mockPlan(OVER)
    vi.mocked(deletePlanOverride).mockResolvedValue(OVER)
    render(<OrganizationPlanPanel tenantId="t1" canManage />)
    await user.click(screen.getByRole('button', { name: /use the plan limit for assets/i }))
    await waitFor(() => expect(deletePlanOverride).toHaveBeenCalledWith('t1', 'assets'))
    expect(setTenantPlan).not.toHaveBeenCalled()
  })
})
