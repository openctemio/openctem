import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const perms = vi.hoisted(() => ({ granted: new Set<string>(['sensors:read']) }))
const api = vi.hoisted(() => ({
  toastError: vi.fn(),
  readiness: { data: undefined as unknown, error: undefined as unknown, isLoading: false },
  mutate: vi.fn(),
  bulk: vi.fn(),
  report: vi.fn(),
  update: vi.fn(),
  calls: [] as (string | null)[],
}))

vi.mock('sonner', () => ({ toast: { error: api.toastError, success: vi.fn() } }))
vi.mock('@/lib/permissions', () => ({
  Permission: { SensorsRead: 'sensors:read' },
  useHasPermission: (p: string) => perms.granted.has(p),
}))
vi.mock('@/lib/api/sensor-readiness-hooks', () => ({
  useSensorReadiness: (id: string | null) => {
    api.calls.push(id)
    return { ...api.readiness, mutate: api.mutate }
  },
}))
vi.mock('@/features/scope/api/use-scope-api', () => ({
  createScopeTargetsBulk: api.bulk,
  invalidateScopeCache: vi.fn(async () => undefined),
}))
vi.mock('@/features/scope/components/add-to-scope-action', () => ({ reportBulkResult: api.report }))
vi.mock('@/lib/api/sensor-grant-hooks', () => ({
  useSensorGrant: () => ({ data: { trust_level: 'new', version: 1 }, mutate: vi.fn() }),
  grantUpdateRequest: (g: object, over: object) => ({ ...g, ...over }),
  updateSensorGrant: api.update,
}))

import { SensorReadinessChecklist, ZoneSensorsReadiness } from '../sensor-readiness'

const readiness = (items: object[], ready = false) => ({
  data: { sensor_id: 's1', ready, items },
  error: undefined,
  isLoading: false,
})

describe('SensorReadinessChecklist', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.calls = []
    perms.granted = new Set(['sensors:read'])
  })

  it('lists the blockers in the API order with their fixes, and hides what does not apply', () => {
    api.readiness = readiness([
      { key: 'online', state: 'ok' },
      {
        key: 'trusted',
        state: 'blocked',
        fix: { action: 'promote', permission: 'sensors:grant:widen', allowed: false },
      },
      {
        key: 'private_targets',
        state: 'unknown',
        fix: {
          action: 'enable_private',
          allowed: true,
          host_line: 'SENSOR_ALLOW_PRIVATE_TARGETS=1',
        },
      },
      { key: 'kill_switch', state: 'not_applicable' },
      { key: 'networks', state: 'ok', count: 1 },
      { key: 'scope', state: 'waiting', count: 1 },
    ])
    render(<SensorReadinessChecklist sensorId="s1" />)
    const rows = screen.getAllByRole('listitem').map((li) => li.getAttribute('data-testid'))
    expect(rows).toEqual([
      'readiness-online',
      'readiness-trusted',
      'readiness-private_targets',
      'readiness-networks',
      'readiness-scope',
    ])
    // Not allowed: who may fix it, no button.
    expect(screen.getByText(/sensors:grant:widen permission can fix this/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Trust this sensor' })).toBeNull()
    // A host step: the line to copy.
    expect(screen.getByText('SENSOR_ALLOW_PRIVATE_TARGETS=1')).toBeInTheDocument()
    expect(screen.getByText('1 of its networks wait for a scope approval.')).toBeInTheDocument()
    expect(screen.getByText('Fix these in order')).toBeInTheDocument()
  })

  it('adds the missing networks to scope through the scope service', async () => {
    api.readiness = readiness([
      {
        key: 'scope',
        state: 'blocked',
        count: 2,
        fix: {
          action: 'add_scope',
          permission: 'attack_surface:scope:write',
          allowed: true,
          patterns: ['10.0.0.0/16', '192.168.1.7/32'],
        },
      },
    ])
    api.bulk.mockResolvedValue({ created: 2 })
    const user = userEvent.setup()
    render(<SensorReadinessChecklist sensorId="s1" />)
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    await waitFor(() => expect(api.bulk).toHaveBeenCalledTimes(1))
    expect(api.bulk.mock.calls[0][0].items).toEqual([
      { target_type: 'cidr', pattern: '10.0.0.0/16' },
      { target_type: 'ip_address', pattern: '192.168.1.7' },
    ])
    await waitFor(() => expect(api.mutate).toHaveBeenCalled())
  })

  it('promotes after the same confirmation as the Grant section', async () => {
    api.readiness = readiness([
      {
        key: 'trusted',
        state: 'blocked',
        fix: { action: 'promote', permission: 'sensors:grant:widen', allowed: true },
      },
    ])
    api.update.mockResolvedValue({ trust_level: 'trusted' })
    const user = userEvent.setup()
    render(<SensorReadinessChecklist sensorId="s1" />)
    await user.click(screen.getByRole('button', { name: 'Trust this sensor' }))
    expect(api.update).not.toHaveBeenCalled()
    await user.click(await screen.findByRole('button', { name: 'Promote' }))
    await waitFor(() =>
      expect(api.update).toHaveBeenCalledWith(
        's1',
        expect.objectContaining({ trust_level: 'trusted' })
      )
    )
  })

  it('answers a refused step-up the way the Grant section does, and keeps the sensor New', async () => {
    api.readiness = readiness([
      {
        key: 'trusted',
        state: 'blocked',
        fix: { action: 'promote', permission: 'sensors:grant:widen', allowed: true },
      },
    ])
    // The API client already opened its re-authentication dialog and the
    // person cancelled it: the original STEP_UP_REQUIRED error reaches us.
    api.update.mockRejectedValue(
      Object.assign(new Error('step-up'), { statusCode: 403, code: 'STEP_UP_REQUIRED' })
    )
    const user = userEvent.setup()
    render(<SensorReadinessChecklist sensorId="s1" />)
    await user.click(screen.getByRole('button', { name: 'Trust this sensor' }))
    await user.click(await screen.findByRole('button', { name: 'Promote' }))
    await waitFor(() =>
      expect(api.toastError).toHaveBeenCalledWith(
        'Confirm your identity to continue, then try again.'
      )
    )
    expect(api.mutate).not.toHaveBeenCalled()
  })

  it('says when nothing blocks it', () => {
    api.readiness = readiness([{ key: 'online', state: 'ok' }], true)
    render(<SensorReadinessChecklist sensorId="s1" />)
    expect(screen.getByText('Nothing blocks it')).toBeInTheDocument()
  })
})

describe('ZoneSensorsReadiness', () => {
  beforeEach(() => {
    api.calls = []
    perms.granted = new Set(['sensors:read'])
    api.readiness = readiness([
      { key: 'online', state: 'ok' },
      { key: 'trusted', state: 'blocked' },
    ])
  })

  it('shows the blockers of the zone sensors, at most three', () => {
    render(<ZoneSensorsReadiness sensorIds={['a', 'b', 'c', 'd']} />)
    expect(new Set(api.calls)).toEqual(new Set(['a', 'b', 'c']))
    expect(screen.queryAllByTestId('readiness-online')).toHaveLength(0)
    expect(screen.getAllByTestId('readiness-trusted')).toHaveLength(3)
  })

  it('warns about a zone without a sensor, and shows nothing without sensors:read', () => {
    const { unmount } = render(<ZoneSensorsReadiness sensorIds={[]} />)
    expect(screen.getByTestId('zone-no-sensor')).toBeInTheDocument()
    unmount()
    perms.granted = new Set()
    const { container } = render(<ZoneSensorsReadiness sensorIds={['a']} />)
    expect(container).toBeEmptyDOMElement()
  })
})
