import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
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
  expect: vi.fn(),
  revoke: vi.fn(),
  expectation: { data: undefined as unknown },
}))

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 'org-1', slug: 'acme', name: 'Acme', role: 'owner' } }),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: {
    SensorsPair: 'sensors:pair',
    SensorsApprove: 'sensors:approve',
    SensorsWrite: 'sensors:write',
    SensorsRevoke: 'sensors:revoke',
    ScanZonesRead: 'zones:read',
  },
  useHasPermission: (p: string) => perms.granted.has(p),
}))
vi.mock('@/lib/api/scan-zone-hooks', () => ({ useScanZones: () => ({ data: { data: [] } }) }))
vi.mock('@/lib/api/sensor-hooks', () => ({
  invalidateSensorsCache: vi.fn(async () => undefined),
  useSensor: () => ({ data: undefined }),
}))
vi.mock('@/lib/api/sensor-pairing-hooks', () => ({
  REPAIR_REASONS: ['lost_identity', 'host_moved', 'key_compromised', 'install_method'],
  lookupPairing: vi.fn(),
  approvePairing: vi.fn(),
  rejectPairing: vi.fn(),
  createPairingExpectation: api.expect,
  revokeActiveSensorKeys: api.revoke,
  pairingSettled: (s?: string) => ['approved', 'completed', 'denied', 'expired'].includes(s ?? ''),
  usePairingExpectation: (id: string | null) =>
    id ? { ...api.expectation, mutate: vi.fn() } : { data: undefined, mutate: vi.fn() },
  useSensorInstallTemplates: (code: string | null) => ({
    isLoading: false,
    data: {
      docker: `docker run -d \\\n  -e SENSOR_PAIRING_CODE='${code ?? ''}' \\\n  ghcr.io/openctemio/sensor:v1`,
      compose: 'services: {}',
      kubernetes: 'kind: Deployment',
      cli: 'openctemio-sensor pair',
      api_url: 'https://ctem.example.test',
    },
    mutate: vi.fn(),
  }),
}))

import { RepairSensorDialog } from '../sensor-repair-dialog'
import type { Sensor } from '@/lib/api/sensor-types'

const sensor = { id: 's1', name: 'edge-01', status: 'active', auth_kind: 'key_bound' } as Sensor
const future = () => new Date(Date.now() + 9 * 60_000).toISOString()

describe('RepairSensorDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    perms.granted = new Set(['sensors:pair', 'sensors:approve', 'sensors:write'])
    api.expectation = { data: undefined }
    api.expect.mockResolvedValue({
      id: 'p1',
      mode: 'reverse',
      status: 'expecting',
      code: 'K7QM4ZTD',
      expires_at: future(),
      repair_sensor_id: 's1',
    })
    api.revoke.mockResolvedValue(1)
  })

  it('needs a reason, and creates a code for this sensor without revoking its key', async () => {
    const user = userEvent.setup()
    render(<RepairSensorDialog sensor={sensor} open onOpenChange={() => {}} />)
    const create = screen.getByRole('button', { name: 'Create re-pair code' })
    expect(create).toBeDisabled()
    await user.click(screen.getByText('Its identity is lost'))
    expect(screen.getByRole('checkbox', { name: /Revoke the current key now/ })).not.toBeChecked()
    expect(screen.getByText(/current key keeps working until you approve/)).toBeInTheDocument()
    await user.click(create)
    await waitFor(() =>
      expect(api.expect).toHaveBeenCalledWith({
        repair_sensor_id: 's1',
        repair_reason: 'lost_identity',
      })
    )
    expect(api.revoke).not.toHaveBeenCalled()
    expect(await screen.findByText('K7QM-4ZTD')).toBeInTheDocument()
    expect(screen.getByText(/SENSOR_PAIRING_CODE='K7QM-4ZTD'/)).toBeInTheDocument()
    expect(
      screen.getByText(/keeps working with its current key until you approve/)
    ).toBeInTheDocument()
  })

  it('offers to revoke a compromised key at once, before the code is created', async () => {
    const user = userEvent.setup()
    render(<RepairSensorDialog sensor={sensor} open onOpenChange={() => {}} />)
    await user.click(screen.getByText('Its key may be compromised'))
    expect(screen.getByRole('checkbox', { name: /Revoke the current key now/ })).toBeChecked()
    await user.click(screen.getByRole('button', { name: 'Create re-pair code' }))
    await waitFor(() => expect(api.revoke).toHaveBeenCalledWith('s1'))
    expect(api.revoke.mock.invocationCallOrder[0]).toBeLessThan(
      api.expect.mock.invocationCallOrder[0]
    )
    expect(
      await screen.findByText(/was revoked; it is offline until you approve/)
    ).toBeInTheDocument()
  })

  it('does not offer revocation without the permission or for an API-key sensor', async () => {
    perms.granted = new Set(['sensors:pair'])
    const user = userEvent.setup()
    const { unmount } = render(<RepairSensorDialog sensor={sensor} open onOpenChange={() => {}} />)
    await user.click(screen.getByText('Its key may be compromised'))
    expect(
      screen.queryByRole('checkbox', { name: /Revoke the current key now/ })
    ).not.toBeInTheDocument()
    unmount()
    perms.granted = new Set(['sensors:pair', 'sensors:write'])
    render(
      <RepairSensorDialog
        sensor={{ ...sensor, auth_kind: 'bearer' }}
        open
        onOpenChange={() => {}}
      />
    )
    expect(
      screen.queryByRole('checkbox', { name: /Revoke the current key now/ })
    ).not.toBeInTheDocument()
  })

  it('offers a new code once the re-pair code expired', async () => {
    api.expectation = {
      data: {
        id: 'p1',
        mode: 'reverse',
        status: 'expired',
        expires_at: future(),
        repair_sensor_id: 's1',
      },
    }
    const user = userEvent.setup()
    render(<RepairSensorDialog sensor={sensor} open onOpenChange={() => {}} />)
    await user.click(screen.getByText('The host was rebuilt or moved'))
    await user.click(screen.getByRole('button', { name: 'Create re-pair code' }))
    expect(
      await screen.findByText(/This re-pair code expired before it was approved/)
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Get a new code' })).toBeInTheDocument()
  })
})
