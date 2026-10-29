import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
Element.prototype.scrollIntoView ??= () => {}
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}

const perms = vi.hoisted(() => ({ granted: new Set<string>() }))
const api = vi.hoisted(() => ({
  tokens: [] as unknown[],
  pending: [] as unknown[],
  create: vi.fn(),
  revoke: vi.fn(),
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
vi.mock('@/lib/api/sensor-hooks', () => ({ invalidateSensorsCache: vi.fn() }))
vi.mock('@/lib/api/sensor-enrollment-hooks', () => ({
  useEnrollmentTokens: () => ({ data: { items: api.tokens }, isLoading: false }),
  usePendingPairings: () => ({ data: { items: api.pending } }),
  createEnrollmentToken: api.create,
  revokeEnrollmentToken: api.revoke,
  refreshPendingPairings: vi.fn(),
}))

import { EnrollmentTokensPanel } from '../enrollment-tokens-panel'

const token = (over: Record<string, unknown> = {}) => ({
  id: 't1',
  name: 'k8s-prod',
  token_hint: 'ab12',
  state: 'active',
  max_uses: 20,
  use_count: 3,
  require_approval: false,
  sensor_type: 'worker',
  zone_ids: [],
  labels: {},
  allowed_cidrs: [],
  created_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 86_400_000).toISOString(),
  last_used_at: new Date(Date.now() - 3_600_000).toISOString(),
  last_used_from: '10.2.0.4',
  ...over,
})

describe('EnrollmentTokensPanel', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    perms.granted = new Set(['sensors:read', 'sensors:pair', 'sensors:approve', 'zones:read'])
    api.tokens = [token()]
    api.pending = []
  })

  it('lists tokens with uses, last use and approval, never the token', () => {
    render(<EnrollmentTokensPanel />)
    const row = screen.getByRole('row', { name: /k8s-prod/ })
    expect(within(row).getByText('3 of 20')).toBeInTheDocument()
    expect(within(row).getByText('10.2.0.4')).toBeInTheDocument()
    expect(within(row).getByText('Automatic')).toBeInTheDocument()
    expect(within(row).getByText('ends with ab12')).toBeInTheDocument()
    expect(screen.queryByText(/octe_/)).toBeNull()
  })

  it('hides create and revoke without sensors:approve', () => {
    perms.granted = new Set(['sensors:read'])
    render(<EnrollmentTokensPanel />)
    expect(screen.queryByRole('button', { name: 'Create token' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Revoke' })).toBeNull()
  })

  it('creates a token with the presets and shows it once behind the close guard', async () => {
    api.create.mockResolvedValue(token({ id: 't2', name: 'lab', token: 'octe_SECRETVALUE' }))
    const user = userEvent.setup()
    render(<EnrollmentTokensPanel />)
    await user.click(screen.getByRole('button', { name: 'Create token' }))
    await user.type(screen.getByLabelText('Name'), 'lab')
    await user.click(screen.getByRole('button', { name: 'dmz' }))
    await user.type(screen.getByLabelText('Allowed source addresses (optional)'), '10.20.0.0/16')
    await user.type(screen.getByLabelText('Labels (optional)'), 'env=lab')
    await user.click(screen.getByRole('switch'))
    await user.click(
      within(screen.getByRole('dialog')).getByRole('button', { name: 'Create token' })
    )
    await waitFor(() => expect(api.create).toHaveBeenCalledTimes(1))
    expect(api.create).toHaveBeenCalledWith({
      name: 'lab',
      ttl_hours: 24,
      max_uses: 10,
      require_approval: true,
      grant_profile: 'internal-network-scanner',
      zone_ids: ['z1'],
      labels: { env: 'lab' },
      allowed_cidrs: ['10.20.0.0/16'],
    })
    expect(await screen.findByText('Copy the token now')).toBeInTheDocument()
    expect(screen.getByLabelText('Enrollment token')).toHaveValue('octe_SECRETVALUE')
  }, 30_000)

  it('will not send an invalid form', async () => {
    const user = userEvent.setup()
    render(<EnrollmentTokensPanel />)
    await user.click(screen.getByRole('button', { name: 'Create token' }))
    await user.type(screen.getByLabelText('Name'), 'x')
    await user.type(screen.getByLabelText('Allowed source addresses (optional)'), 'nope')
    expect(
      within(screen.getByRole('dialog')).getByRole('button', { name: 'Create token' })
    ).toBeDisabled()
  })

  it('revokes after confirmation', async () => {
    api.revoke.mockResolvedValue(token({ state: 'revoked' }))
    const user = userEvent.setup()
    render(<EnrollmentTokensPanel />)
    await user.click(screen.getByRole('button', { name: 'Revoke' }))
    await user.click(
      within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Revoke' })
    )
    await waitFor(() => expect(api.revoke).toHaveBeenCalledWith('t1'))
  })

  it('lists sensors waiting for approval', () => {
    api.pending = [
      {
        id: 'p1',
        status: 'pending',
        sas: '512 · tiger · violet · anchor',
        host_facts: { hostname: 'node-7', sensor_version: '0.25.0' },
        source_ip: '10.2.0.9',
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      },
    ]
    render(<EnrollmentTokensPanel />)
    const card = screen.getByTestId('pending-approvals')
    expect(within(card).getByText('Waiting for approval (1)')).toBeInTheDocument()
    expect(within(card).getByText('node-7')).toBeInTheDocument()
  })
})
