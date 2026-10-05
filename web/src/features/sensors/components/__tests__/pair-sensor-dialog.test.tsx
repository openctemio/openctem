import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ApiClientError } from '@/lib/api/error-handler'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
// Radix Select calls these; jsdom does not implement them.
Element.prototype.scrollIntoView ??= () => {}
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}

const perms = vi.hoisted(() => ({ granted: new Set<string>() }))
const api = vi.hoisted(() => ({
  lookup: vi.fn(),
  expect: vi.fn(),
  approve: vi.fn(),
  reject: vi.fn(),
  expectation: { data: undefined as unknown, error: undefined as unknown },
  expectationIds: [] as (string | null)[],
}))

vi.mock('@/lib/permissions', () => ({
  Permission: {
    SensorsPair: 'sensors:pair',
    SensorsApprove: 'sensors:approve',
    ScanZonesRead: 'zones:read',
  },
  useHasPermission: (p: string) => perms.granted.has(p),
}))
vi.mock('@/lib/api/scan-zone-hooks', () => ({
  useScanZones: () => ({ data: { data: [{ id: 'z1', name: 'dmz' }] } }),
}))
vi.mock('@/lib/api/sensor-hooks', () => ({
  invalidateSensorsCache: vi.fn(async () => undefined),
}))
vi.mock('@/lib/api/sensor-pairing-hooks', () => ({
  lookupPairing: api.lookup,
  createPairingExpectation: api.expect,
  approvePairing: api.approve,
  rejectPairing: api.reject,
  pairingSettled: (s?: string) => ['approved', 'completed', 'denied', 'expired'].includes(s ?? ''),
  usePairingExpectation: (id: string | null) => {
    api.expectationIds.push(id)
    return id ? api.expectation : { data: undefined, error: undefined }
  },
}))

import { PairSensorButton, PairSensorDialog } from '../pair-sensor-dialog'

const future = () => new Date(Date.now() + 9 * 60_000).toISOString()

function pendingView(over: Record<string, unknown> = {}) {
  return {
    id: 'p1',
    mode: 'forward',
    status: 'pending',
    sas: '512 · tiger · violet · anchor',
    key_fingerprint: 'SHA256:abc',
    host_facts: { hostname: 'dmz-01', os: 'linux', arch: 'amd64', sensor_version: '0.9.0' },
    source_ip: '203.0.113.7',
    expires_at: future(),
    step_up: 'totp',
    ...over,
  }
}

async function findByCode(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText('Pairing code'), 'k7qm-4ztd')
  await user.click(screen.getByRole('button', { name: /find sensor/i }))
}

describe('PairSensorDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    perms.granted = new Set(['sensors:pair', 'sensors:approve', 'zones:read'])
    api.expectation = { data: undefined, error: undefined }
    api.expectationIds = []
  })

  it('looks up the normalised code and shows the fingerprint, host facts and source address', async () => {
    api.lookup.mockResolvedValue(pendingView())
    const user = userEvent.setup()
    render(<PairSensorDialog open onOpenChange={() => {}} />)
    await findByCode(user)
    expect(api.lookup).toHaveBeenCalledWith('K7QM4ZTD')
    expect(await screen.findByTestId('pairing-fingerprint')).toHaveTextContent(
      '512 · tiger · violet · anchor'
    )
    expect(screen.getByText('dmz-01')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.7')).toBeInTheDocument()
    expect(screen.getByText('SHA256:abc')).toBeInTheDocument()
  })

  it('answers every miss with the same message (uniform 404)', async () => {
    api.lookup.mockRejectedValue(new ApiClientError('Pairing request not found', 'NOT_FOUND', 404))
    const user = userEvent.setup()
    render(<PairSensorDialog open onOpenChange={() => {}} />)
    await findByCode(user)
    expect(await screen.findByRole('alert')).toHaveTextContent('Code not found or expired')
  })

  it('says the same for input that cannot be a code, without calling the API', async () => {
    const user = userEvent.setup()
    render(<PairSensorDialog open onOpenChange={() => {}} />)
    await user.type(screen.getByLabelText('Pairing code'), 'nope')
    await user.click(screen.getByRole('button', { name: /find sensor/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Code not found or expired')
    expect(api.lookup).not.toHaveBeenCalled()
  })

  it('reports rate limiting', async () => {
    api.lookup.mockRejectedValue(new ApiClientError('slow down', 'RATE_LIMIT_EXCEEDED', 429))
    const user = userEvent.setup()
    render(<PairSensorDialog open onOpenChange={() => {}} />)
    await findByCode(user)
    expect(await screen.findByRole('alert')).toHaveTextContent(/too many attempts/i)
  })

  it('keeps Approve disabled until the fingerprint tick and the step-up code are given', async () => {
    api.lookup.mockResolvedValue(pendingView())
    const user = userEvent.setup()
    render(<PairSensorDialog open onOpenChange={() => {}} />)
    await findByCode(user)
    const approve = await screen.findByRole('button', { name: /^approve$/i })
    expect(approve).toBeDisabled()
    await user.type(screen.getByLabelText('Authenticator code'), '123456')
    expect(approve).toBeDisabled()
    await user.click(screen.getByLabelText(/fingerprint shown on the sensor console matches/i))
    expect(approve).toBeEnabled()
  })

  it('sends the confirmation, the step-up proof, the code and the default narrow profile', async () => {
    api.lookup.mockResolvedValue(pendingView())
    api.approve.mockResolvedValue({ ...pendingView(), status: 'approved', sensor_id: 's1' })
    const user = userEvent.setup()
    render(<PairSensorDialog open onOpenChange={() => {}} />)
    await findByCode(user)
    await user.click(await screen.findByRole('button', { name: 'dmz' }))
    await user.click(screen.getByLabelText(/fingerprint shown on the sensor console matches/i))
    await user.type(screen.getByLabelText('Authenticator code'), '123456')
    await user.click(screen.getByRole('button', { name: /^approve$/i }))
    await waitFor(() => expect(api.approve).toHaveBeenCalledTimes(1))
    expect(api.approve).toHaveBeenCalledWith('p1', {
      code: 'K7QM4ZTD',
      fingerprint_confirmed: true,
      step_up: { totp: '123456' },
      name: 'dmz-01',
      type: 'worker',
      zone_ids: ['z1'],
      grant_profile: 'internal-network-scanner',
    })
    expect(await screen.findByText('Sensor approved')).toBeInTheDocument()
  })

  it('asks for the password when the account has no TOTP, and clears it after a failure', async () => {
    api.lookup.mockResolvedValue(pendingView({ step_up: 'password' }))
    api.approve.mockRejectedValue(new ApiClientError('no', 'STEP_UP_FAILED', 403))
    const user = userEvent.setup()
    render(<PairSensorDialog open onOpenChange={() => {}} />)
    await findByCode(user)
    await user.click(
      await screen.findByLabelText(/fingerprint shown on the sensor console matches/i)
    )
    await user.type(screen.getByLabelText('Your password'), 'hunter2')
    await user.click(screen.getByRole('button', { name: /^approve$/i }))
    expect(api.approve.mock.calls[0][1].step_up).toEqual({ password: 'hunter2' })
    expect(await screen.findByRole('alert')).toHaveTextContent(/re-authentication failed/i)
    expect(screen.getByLabelText('Your password')).toHaveValue('')
  })

  it('never offers the broad legacy grant', async () => {
    api.lookup.mockResolvedValue(pendingView())
    const user = userEvent.setup()
    render(<PairSensorDialog open onOpenChange={() => {}} />)
    await findByCode(user)
    await user.click(await screen.findByTestId('grant-profile'))
    expect(screen.queryByRole('option', { name: /legacy/i })).not.toBeInTheDocument()
    expect(screen.getAllByRole('option').length).toBe(6)
  })

  it('cannot approve without sensors:approve', async () => {
    perms.granted = new Set(['sensors:pair'])
    api.lookup.mockResolvedValue(pendingView())
    const user = userEvent.setup()
    render(<PairSensorDialog open onOpenChange={() => {}} />)
    await findByCode(user)
    await user.click(
      await screen.findByLabelText(/fingerprint shown on the sensor console matches/i)
    )
    await user.type(screen.getByLabelText('Authenticator code'), '123456')
    expect(screen.getByRole('button', { name: /^approve$/i })).toBeDisabled()
    expect(screen.getByText(/permission to approve sensors/i)).toBeInTheDocument()
  })

  it('shows no approval form before the sensor revealed its nonce', async () => {
    api.lookup.mockResolvedValue(pendingView({ sas: '' }))
    const user = userEvent.setup()
    render(<PairSensorDialog open onOpenChange={() => {}} />)
    await findByCode(user)
    expect(await screen.findByText(/has not finished its handshake/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^approve$/i })).not.toBeInTheDocument()
  })

  it('rejects a request', async () => {
    api.lookup.mockResolvedValue(pendingView())
    api.reject.mockResolvedValue(undefined)
    const onOpenChange = vi.fn()
    const user = userEvent.setup()
    render(<PairSensorDialog open onOpenChange={onOpenChange} />)
    await findByCode(user)
    await user.click(await screen.findByRole('button', { name: /^reject$/i }))
    expect(api.reject).toHaveBeenCalledWith('p1')
    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false))
  })

  it('reverse mode: shows the pair command, polls, then shows the fingerprint to compare', async () => {
    api.expect.mockResolvedValue({
      id: 'e1',
      mode: 'reverse',
      status: 'expecting',
      code: 'K7QM4ZTD',
      expires_at: future(),
    })
    const user = userEvent.setup()
    const { rerender } = render(<PairSensorDialog open onOpenChange={() => {}} />)
    await user.click(screen.getByRole('tab', { name: /expect a sensor/i }))
    await user.click(screen.getByRole('button', { name: /get a code/i }))
    expect(await screen.findByText('openctemio-sensor pair K7QM-4ZTD')).toBeInTheDocument()
    expect(screen.getByText(/waiting for the sensor to connect/i)).toBeInTheDocument()
    expect(api.expectationIds).toContain('e1')

    // The poll now returns the connected sensor.
    api.expectation = { data: pendingView({ id: 'e1', mode: 'reverse' }), error: undefined }
    await act(async () => rerender(<PairSensorDialog open onOpenChange={() => {}} />))
    expect(await screen.findByTestId('pairing-fingerprint')).toHaveTextContent('tiger')
    expect(screen.getByRole('button', { name: /^approve$/i })).toBeDisabled()
  })
})

describe('PairSensorButton', () => {
  it('is hidden without sensors:pair', () => {
    perms.granted = new Set(['sensors:write'])
    const { container } = render(<PairSensorButton onClick={() => {}} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows with sensors:pair', () => {
    perms.granted = new Set(['sensors:pair'])
    render(<PairSensorButton onClick={() => {}} />)
    expect(screen.getByRole('button', { name: /pair a sensor/i })).toBeInTheDocument()
  })
})
