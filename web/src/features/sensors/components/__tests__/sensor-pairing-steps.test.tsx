import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
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

const tenant = vi.hoisted(() => ({
  current: { id: 'org-1', slug: 'acme', name: 'Acme', role: 'owner' } as {
    id: string
    slug: string
    name?: string
    role: string
  } | null,
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: tenant.current }),
}))

vi.mock('@/lib/permissions', () => ({
  Permission: {
    SensorsPair: 'sensors:pair',
    SensorsApprove: 'sensors:approve',
    SensorsRead: 'sensors:read',
    ScanZonesRead: 'zones:read',
  },
  useHasPermission: (p: string) => perms.granted.has(p),
}))
vi.mock('@/lib/api/scan-zone-hooks', () => ({
  useScanZones: () => ({ data: { data: [{ id: 'z1', name: 'dmz' }] } }),
}))
vi.mock('@/lib/api/sensor-hooks', () => ({
  invalidateSensorsCache: vi.fn(async () => undefined),
  useTenantSensorStats: (cfg?: { isPaused?: () => boolean }) => ({
    data: cfg?.isPaused?.()
      ? undefined
      : { products: [{ id: 'openctemio-sensor', image: 'ghcr.io/example/sensor:1.2.3' }] },
  }),
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

import { EnterCodePanel } from '../sensor-pairing-steps'

const onApproved = vi.fn()
const onClose = vi.fn()
const panel = () => <EnterCodePanel onApproved={onApproved} onClose={onClose} />

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
    source_network: 'public',
    approver_ip: '198.51.100.20',
    organization_id: 'org-1',
    organization_name: 'Acme',
    created_at: new Date(Date.now() - 3 * 60_000).toISOString(),
    expires_at: future(),
    step_up: 'totp',
    ...over,
  }
}

async function findByCode(user: ReturnType<typeof userEvent.setup>) {
  // A complete code looks the sensor up on its own.
  await user.type(screen.getByLabelText('Pairing code'), 'k7qm-4ztd')
}

describe('EnterCodePanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    perms.granted = new Set(['sensors:pair', 'sensors:approve', 'zones:read'])
    api.expectation = { data: undefined, error: undefined }
    api.expectationIds = []
    tenant.current = { id: 'org-1', slug: 'acme', name: 'Acme', role: 'owner' }
  })

  it('looks up the normalised code and shows the fingerprint, host facts and source address', async () => {
    api.lookup.mockResolvedValue(pendingView())
    const user = userEvent.setup()
    render(panel())
    await findByCode(user)
    expect(api.lookup).toHaveBeenCalledWith('K7QM4ZTD')
    expect(await screen.findByTestId('pairing-fingerprint')).toHaveTextContent(
      '512, tiger, violet, anchor'
    )
    expect(screen.getByText('dmz-01')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.7 (public internet)')).toBeInTheDocument()
    expect(screen.getByText('198.51.100.20')).toBeInTheDocument()
    expect(screen.getByText('3 min ago')).toBeInTheDocument()
    expect(screen.getByText('SHA256:abc')).toBeInTheDocument()
  })

  it('answers every miss with the same message (uniform 404)', async () => {
    api.lookup.mockRejectedValue(new ApiClientError('Pairing request not found', 'NOT_FOUND', 404))
    const user = userEvent.setup()
    render(panel())
    await findByCode(user)
    expect(await screen.findByRole('alert')).toHaveTextContent('Code not found or expired')
  })

  it('says the same for input that cannot be a code, without calling the API', async () => {
    const user = userEvent.setup()
    render(panel())
    await user.type(screen.getByLabelText('Pairing code'), 'nope')
    await user.click(screen.getByRole('button', { name: /find sensor/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Code not found or expired')
    expect(api.lookup).not.toHaveBeenCalled()
  })

  it('reports rate limiting', async () => {
    api.lookup.mockRejectedValue(new ApiClientError('slow down', 'RATE_LIMIT_EXCEEDED', 429))
    const user = userEvent.setup()
    render(panel())
    await findByCode(user)
    expect(await screen.findByRole('alert')).toHaveTextContent(/too many attempts/i)
  })

  it('keeps Approve disabled until the fingerprint tick and the step-up code are given', async () => {
    api.lookup.mockResolvedValue(pendingView())
    const user = userEvent.setup()
    render(panel())
    await findByCode(user)
    const approve = await screen.findByRole('button', { name: /^approve into acme$/i })
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
    render(panel())
    await findByCode(user)
    await user.click(await screen.findByRole('button', { name: 'dmz' }))
    await user.click(screen.getByLabelText(/fingerprint shown on the sensor console matches/i))
    await user.type(screen.getByLabelText('Authenticator code'), '123456')
    await user.click(screen.getByRole('button', { name: /^approve into acme$/i }))
    await waitFor(() => expect(api.approve).toHaveBeenCalledTimes(1))
    expect(api.approve).toHaveBeenCalledWith('p1', {
      code: 'K7QM4ZTD',
      fingerprint_confirmed: true,
      organization_id: 'org-1',
      step_up: { totp: '123456' },
      name: 'dmz-01',
      type: 'worker',
      zone_ids: ['z1'],
      grant_profile: 'internal-network-scanner',
    })
    await waitFor(() =>
      expect(onApproved).toHaveBeenCalledWith(expect.objectContaining({ sensor_id: 's1' }))
    )
  })

  it('asks for the password when the account has no TOTP, and clears it after a failure', async () => {
    api.lookup.mockResolvedValue(pendingView({ step_up: 'password' }))
    api.approve.mockRejectedValue(new ApiClientError('no', 'STEP_UP_FAILED', 403))
    const user = userEvent.setup()
    render(panel())
    await findByCode(user)
    await user.click(
      await screen.findByLabelText(/fingerprint shown on the sensor console matches/i)
    )
    await user.type(screen.getByLabelText('Your password'), 'hunter2')
    await user.click(screen.getByRole('button', { name: /^approve into acme$/i }))
    expect(api.approve.mock.calls[0][1].step_up).toEqual({ password: 'hunter2' })
    expect(await screen.findByRole('alert')).toHaveTextContent(/re-authentication failed/i)
    expect(screen.getByLabelText('Your password')).toHaveValue('')
  })

  it('never offers the broad legacy grant', async () => {
    api.lookup.mockResolvedValue(pendingView())
    const user = userEvent.setup()
    render(panel())
    await findByCode(user)
    await user.click(await screen.findByTestId('grant-profile'))
    expect(screen.queryByRole('option', { name: /legacy/i })).not.toBeInTheDocument()
    expect(screen.getAllByRole('option').length).toBe(7)
  })

  it('cannot approve without sensors:approve', async () => {
    perms.granted = new Set(['sensors:pair'])
    api.lookup.mockResolvedValue(pendingView())
    const user = userEvent.setup()
    render(panel())
    await findByCode(user)
    await user.click(
      await screen.findByLabelText(/fingerprint shown on the sensor console matches/i)
    )
    await user.type(screen.getByLabelText('Authenticator code'), '123456')
    expect(screen.getByRole('button', { name: /^approve into acme$/i })).toBeDisabled()
    expect(screen.getByText(/permission to approve sensors/i)).toBeInTheDocument()
  })

  it('shows no approval form before the sensor revealed its nonce', async () => {
    api.lookup.mockResolvedValue(pendingView({ sas: '' }))
    const user = userEvent.setup()
    render(panel())
    await findByCode(user)
    expect(await screen.findByText(/has not finished its handshake/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^approve into acme$/i })).not.toBeInTheDocument()
  })

  it('names the organization the sensor joins and warns against codes sent by others', async () => {
    api.lookup.mockResolvedValue(pendingView())
    const user = userEvent.setup()
    render(panel())
    expect(screen.getByTestId('pairing-phishing-warning')).toHaveTextContent(
      /never approve a code someone sent you/i
    )
    await findByCode(user)
    expect(await screen.findByTestId('pairing-organization')).toHaveTextContent(
      'The sensor joins Acme'
    )
    expect(screen.getByTestId('pairing-phishing-warning')).toBeInTheDocument()
  })

  it('refuses to approve once the page shows another organization than the review', async () => {
    api.lookup.mockResolvedValue(
      pendingView({ organization_id: 'org-2', organization_name: 'Other' })
    )
    const user = userEvent.setup()
    render(panel())
    await findByCode(user)
    expect(await screen.findByTestId('pairing-org-mismatch')).toHaveTextContent(
      /organization changed/i
    )
    expect(screen.queryByRole('button', { name: /^approve/i })).not.toBeInTheDocument()
  })

  it('explains an approval the API refused after a switch of organization', async () => {
    api.lookup.mockResolvedValue(pendingView())
    api.approve.mockRejectedValue(new ApiClientError('changed', 'ORGANIZATION_MISMATCH', 409))
    const user = userEvent.setup()
    render(panel())
    await findByCode(user)
    await user.click(
      await screen.findByLabelText(/fingerprint shown on the sensor console matches/i)
    )
    await user.type(screen.getByLabelText('Authenticator code'), '123456')
    await user.click(screen.getByRole('button', { name: /^approve into acme$/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/organization changed since/i)
  })

  it('marks a request from a private address and its provider', async () => {
    api.lookup.mockResolvedValue(
      pendingView({ source_ip: '10.1.2.3', source_network: 'private', source_provider: '' })
    )
    const user = userEvent.setup()
    render(panel())
    await findByCode(user)
    expect(await screen.findByText('10.1.2.3 (private network)')).toBeInTheDocument()
  })

  it('rejects a request', async () => {
    api.lookup.mockResolvedValue(pendingView())
    api.reject.mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(panel())
    await findByCode(user)
    await user.click(await screen.findByRole('button', { name: /^reject$/i }))
    expect(api.reject).toHaveBeenCalledWith('p1', 'K7QM4ZTD')
    await waitFor(() => expect(onClose).toHaveBeenCalled())
  })
})
