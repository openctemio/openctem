import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import type { AdminLimitsResponse, SelfServiceLimitsResponse } from '@/lib/api/generated'
import { parseLimit } from '@/features/limits/lib/limit-keys'
import { AdminApiError } from '@console/lib/admin-api/client'
import {
  deleteTenantLimit,
  putTenantLimit,
  saveSelfServiceLimits,
  useTenantLimits,
} from '../api/use-limits'
import { SelfServiceLimitsForm } from '../components/self-service-limits-form'
import { OrganizationLimitsPanel } from '../components/organization-limits-panel'

vi.mock('../api/use-limits', async (orig) => ({
  ...(await orig<typeof import('../api/use-limits')>()),
  saveSelfServiceLimits: vi.fn(),
  useTenantLimits: vi.fn(),
  putTenantLimit: vi.fn(),
  deleteTenantLimit: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const EMPTY: SelfServiceLimitsResponse = { limits: {}, keys: [], version: 0, sources: ['none'] }

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

describe('SelfServiceLimitsForm', () => {
  beforeEach(() => vi.clearAllMocks())

  it('starts empty (no limits) and shows no source on a self-hosted install', () => {
    render(<SelfServiceLimitsForm defaults={EMPTY} canEdit onSaved={vi.fn()} />)
    expect(screen.getByLabelText('Seats')).toHaveValue('')
    expect(screen.getByLabelText('Organizations per person')).toHaveValue('')
    expect(screen.queryByTestId('limit-sources')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('names the service operator when the control plane is a source', () => {
    render(
      <SelfServiceLimitsForm
        defaults={{ ...EMPTY, sources: ['control_plane'] }}
        canEdit
        onSaved={vi.fn()}
      />
    )
    expect(screen.getByTestId('limit-sources')).toHaveTextContent('The service operator')
  })

  it('a read-only administrator cannot change them', () => {
    render(<SelfServiceLimitsForm defaults={EMPTY} canEdit={false} onSaved={vi.fn()} />)
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('Seats')).toBeDisabled()
  })

  it('refuses a value that is not a whole number', async () => {
    const user = userEvent.setup()
    render(<SelfServiceLimitsForm defaults={EMPTY} canEdit onSaved={vi.fn()} />)
    await user.type(screen.getByLabelText('Seats'), '-3')
    expect(screen.getByText(/whole number of 0 or more/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('saves only the limits that are set, with the code and the version read', async () => {
    const user = userEvent.setup()
    const onSaved = vi.fn()
    vi.mocked(saveSelfServiceLimits).mockResolvedValue({ ...EMPTY, version: 1 })
    render(<SelfServiceLimitsForm defaults={EMPTY} canEdit onSaved={onSaved} />)
    await user.type(screen.getByLabelText('Seats'), '5')
    await user.type(screen.getByLabelText('Organizations per person'), '1')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    const confirm = screen.getByRole('button', { name: 'Confirm' })
    expect(confirm).toBeDisabled()
    await user.type(screen.getByLabelText(/code from your authenticator/i), '123456')
    await user.click(confirm)

    await waitFor(() => expect(saveSelfServiceLimits).toHaveBeenCalled())
    expect(vi.mocked(saveSelfServiceLimits).mock.calls[0][0]).toEqual({
      limits: { seats: 5, orgs_per_user: 1 },
      version: 0,
      totp_code: '123456',
    })
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
  })

  it('a wrong code keeps the dialog open with the reason', async () => {
    const user = userEvent.setup()
    vi.mocked(saveSelfServiceLimits).mockRejectedValue(
      new AdminApiError('Invalid or already used code', 401)
    )
    render(<SelfServiceLimitsForm defaults={EMPTY} canEdit onSaved={vi.fn()} />)
    await user.type(screen.getByLabelText('Assets'), '1000')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await user.type(screen.getByLabelText(/code from your authenticator/i), '000000')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByText('Invalid or already used code')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Confirm' })).toBeInTheDocument()
  })
})

const OVER: AdminLimitsResponse = {
  applies: true,
  over_limit: true,
  denied_features: [],
  limits: [
    {
      key: 'seats',
      limit: 5,
      used: 7,
      origin: 'control_plane',
      reason: 'service tier',
      over_limit: true,
    },
    { key: 'assets', limit: 1000, used: 20, origin: 'operator', reason: 'pilot' },
    { key: 'sensors', limit: -1, used: 3 },
  ],
}

function mockLimits(data: AdminLimitsResponse) {
  const mutate = vi.fn()
  vi.mocked(useTenantLimits).mockReturnValue({
    data,
    error: undefined,
    isLoading: false,
    isValidating: false,
    mutate,
  } as unknown as ReturnType<typeof useTenantLimits>)
  return mutate
}

describe('OrganizationLimitsPanel', () => {
  beforeEach(() => vi.clearAllMocks())

  it('flags an organization over its limits and says who set each one', () => {
    mockLimits(OVER)
    render(<OrganizationLimitsPanel tenantId="t1" canManage />)
    expect(screen.getAllByText('Over limit').length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(screen.getByText(/set by the service operator: service tier/i)).toBeInTheDocument()
    expect(screen.getByText(/set by an administrator: pilot/i)).toBeInTheDocument()
    expect(screen.getAllByText('Unlimited').length).toBeGreaterThan(0)
  })

  it('a limit set by the service operator cannot be edited here', () => {
    mockLimits(OVER)
    render(<OrganizationLimitsPanel tenantId="t1" canManage />)
    expect(screen.queryByRole('button', { name: /set the seats limit/i })).not.toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /remove the seats limit/i })
    ).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /set the assets limit/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /set the sensors limit/i })).toBeInTheDocument()
  })

  it('a read-only administrator cannot change a limit', () => {
    mockLimits(OVER)
    render(<OrganizationLimitsPanel tenantId="t1" canManage={false} />)
    expect(screen.queryByRole('button', { name: /set the assets limit/i })).not.toBeInTheDocument()
    expect(screen.getByText(/needs an operations admin/i)).toBeInTheDocument()
  })

  it('a limit needs a reason before it can be saved', async () => {
    const user = userEvent.setup()
    mockLimits(OVER)
    vi.mocked(putTenantLimit).mockResolvedValue(OVER)
    render(<OrganizationLimitsPanel tenantId="t1" canManage />)
    await user.click(screen.getByRole('button', { name: /set the sensors limit/i }))
    const save = screen.getByRole('button', { name: 'Save' })
    await user.type(screen.getByLabelText('Limit'), '10')
    expect(save).toBeDisabled()
    await user.type(screen.getByLabelText('Reason'), 'pilot extension')
    expect(save).toBeEnabled()
    await user.click(save)
    await waitFor(() =>
      expect(putTenantLimit).toHaveBeenCalledWith('t1', 'sensors', {
        value: 10,
        reason: 'pilot extension',
        expires_at: undefined,
      })
    )
  })

  it('removing a limit asks first', async () => {
    const user = userEvent.setup()
    mockLimits(OVER)
    vi.mocked(deleteTenantLimit).mockResolvedValue(OVER)
    render(<OrganizationLimitsPanel tenantId="t1" canManage />)
    await user.click(screen.getByRole('button', { name: /remove the assets limit/i }))
    expect(deleteTenantLimit).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    await user.click(within(dialog).getByRole('button', { name: 'Remove the limit' }))
    await waitFor(() => expect(deleteTenantLimit).toHaveBeenCalledWith('t1', 'assets'))
  })
})
