import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'

import { ApiClientError } from '@/lib/api/error-handler'
import type { Sensor } from '@/lib/api/sensor-types'
import { TooltipProvider } from '@/components/ui/tooltip'

import { hostDirectState, isHostDirect } from '../lib/host-direct'
import {
  MAX_TEST_SENSORS,
  allFinished,
  exitAddresses,
  testableSensors,
  toggleSensor,
} from '../lib/proxy-test'
import type { ProxyPool, ProxyTestOutcome } from '../types'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.releasePointerCapture ??= () => {}
Element.prototype.scrollIntoView ??= () => {}

function sensor(over: Partial<Sensor> & { caps?: string[] }): Sensor {
  const { caps, ...rest } = over
  return {
    id: 's1',
    name: 'Sensor 1',
    status: 'active',
    health: 'online',
    reported: { capabilities: caps ?? ['proxy.test@1'] },
    ...rest,
  } as unknown as Sensor
}

describe('proxy test helpers', () => {
  it('offers only active, online sensors that report proxy.test@1', () => {
    const list = [
      sensor({ id: 'ok' }),
      sensor({ id: 'late', health: 'late' }),
      sensor({ id: 'off', health: 'offline' }),
      sensor({ id: 'dis', status: 'disabled' }),
      sensor({ id: 'old', caps: ['egress.upstream@1'] }),
      sensor({ id: 'none', reported: null }),
    ]
    expect(testableSensors(list).map((s) => s.id)).toEqual(['ok', 'late'])
  })

  it('never selects more than three sensors', () => {
    let sel: string[] = []
    for (const id of ['a', 'b', 'c', 'd']) sel = toggleSensor(sel, id)
    expect(sel).toHaveLength(MAX_TEST_SENSORS)
    expect(sel).not.toContain('d')
    expect(toggleSensor(sel, 'a')).toEqual(['b', 'c'])
  })

  it('knows when every test has ended', () => {
    expect(allFinished([])).toBe(false)
    expect(allFinished([{ status: 'running' }, { status: 'completed' }])).toBe(false)
    expect(
      allFinished([{ status: 'failed' }, { status: 'expired' }, { status: 'completed' }])
    ).toBe(true)
  })

  it('lists each passing exit address once', () => {
    expect(
      exitAddresses([
        { endpoint_id: 'a', address: 'x', ok: true, handshake_ms: 1, exit_ip: '203.0.113.9' },
        { endpoint_id: 'b', address: 'y', ok: true, handshake_ms: 1, exit_ip: '203.0.113.9' },
        { endpoint_id: 'c', address: 'z', ok: false, handshake_ms: 0, exit_ip: '198.51.100.1' },
      ])
    ).toEqual(['203.0.113.9'])
  })
})

describe('host direct-only sensors', () => {
  it('reads the marker the sensor reports', () => {
    expect(isHostDirect(['egress.host-direct@1'])).toBe(true)
    expect(isHostDirect(['egress.upstream@1'])).toBe(false)
    expect(isHostDirect(null)).toBe(false)
  })

  it('runs direct when it inherits or goes direct, and conflicts with a chosen pool', () => {
    const caps = ['egress.host-direct@1']
    expect(hostDirectState('inherit', caps)).toBe('direct-host')
    expect(hostDirectState('direct', caps)).toBe('direct-host')
    expect(hostDirectState('pool:p1', caps)).toBe('host-conflict')
    expect(hostDirectState('inherit', ['egress.upstream@1'])).toBeNull()
  })
})

// The dialog.
let sensors: Sensor[] = []
let outcomes: ProxyTestOutcome[] = []
let started: { command_id: string }[] = []
const startTest = vi.fn()
vi.mock('@/lib/api/sensor-hooks', () => ({
  useSensors: () => ({
    data: { items: sensors },
    error: undefined,
    isLoading: false,
  }),
}))
vi.mock('../api/use-proxy-pool-test', () => ({
  startProxyPoolTest: (...a: unknown[]) => startTest(...a),
  useProxyPoolTestResults: (_pool: string, ids: string[]) => ({
    data: ids.length > 0 ? { items: outcomes } : undefined,
  }),
}))
let assignments: { sensor_id: string; mode: string; pool_id?: string }[] = []
let pools: ProxyPool[] = []
vi.mock('../api/use-proxy-pools', () => ({
  useProxyPools: () => ({ data: { items: pools }, error: undefined, mutate: vi.fn() }),
  useProxyAssignments: () => ({ data: { items: assignments }, error: undefined, mutate: vi.fn() }),
  invalidateProxyPools: vi.fn(),
  setProxyAssignment: vi.fn(),
}))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
}))
const toastError = vi.fn()
vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: (...a: unknown[]) => toastError(...a) },
}))

import { TestPoolButton } from '../components/test-pool-button'
import { SensorNetworkPathSection } from '../components/sensor-network-path-section'

function pool(endpoints = 2): ProxyPool {
  return {
    id: 'p1',
    name: 'Draft',
    description: '',
    enabled: false,
    is_default: false,
    strategy: 'sticky',
    revision: 1,
    assigned_sensors: 0,
    created_at: '2026-10-01T00:00:00Z',
    updated_at: '2026-10-01T00:00:00Z',
    endpoints_text: '',
    endpoints: Array.from({ length: endpoints }, (_, i) => ({
      id: `e${i}`,
      scheme: 'http' as const,
      host: `10.0.0.${i + 5}`,
      port: 3128,
      label: '',
      priority: i,
      enabled: true,
      has_credentials: false,
      health: {
        state: 'probation' as const,
        score: 0.5,
        consecutive_failures: 0,
        ok_total: 0,
        fail_total: 0,
        handshake_ms_p95: 0,
        last_error: '',
        last_ok_at: null,
        last_failure_at: null,
        quarantined_until: null,
      },
    })),
  }
}

function open(p: ProxyPool = pool(), canWrite = true) {
  render(
    <TooltipProvider>
      <TestPoolButton pool={p} canWrite={canWrite} />
    </TooltipProvider>
  )
  fireEvent.click(screen.getByRole('button', { name: 'Test' }))
}

describe('Test button', () => {
  beforeEach(() => {
    cleanup()
    sensors = [
      sensor({ id: 's1', name: 'Edge A' }),
      sensor({ id: 's2', name: 'Edge B' }),
      sensor({ id: 's3', health: 'offline', name: 'Gone' }),
    ]
    outcomes = []
    started = []
    startTest.mockReset()
    toastError.mockReset()
  })

  it('is hidden without write permission and for a pool with no proxy', () => {
    render(
      <TooltipProvider>
        <TestPoolButton pool={pool()} canWrite={false} />
        <TestPoolButton pool={pool(0)} canWrite />
      </TooltipProvider>
    )
    expect(screen.queryByRole('button', { name: 'Test' })).toBeNull()
  })

  it('lists only sensors that can test, and runs the test on the chosen ones', async () => {
    started = [{ command_id: 'c1' }]
    startTest.mockResolvedValue({ items: started })
    open()
    const picker = await screen.findByTestId('test-sensor-picker')
    expect(within(picker).getByText('Edge A')).toBeTruthy()
    expect(within(picker).queryByText('Gone')).toBeNull()
    expect(screen.getByText(/1 other sensors are offline/)).toBeTruthy()
    const run = screen.getByRole('button', { name: 'Run test' }) as HTMLButtonElement
    expect(run.disabled).toBe(true)
    fireEvent.click(screen.getByLabelText('Edge A'))
    fireEvent.click(screen.getByLabelText('Edge B'))
    fireEvent.click(run)
    await waitFor(() => expect(startTest).toHaveBeenCalledWith('p1', ['s1', 's2']))
  })

  it('shows each endpoint with its result, exit address, families and a 443-only proxy', async () => {
    startTest.mockResolvedValue({ items: [{ command_id: 'c1' }] })
    outcomes = [
      {
        command_id: 'c1',
        sensor_id: 's1',
        sensor_name: 'Edge A',
        status: 'completed',
        results: [
          {
            endpoint_id: 'e0',
            address: 'http://10.0.0.5:3128',
            ok: true,
            handshake_ms: 84,
            exit_ip: '203.0.113.9',
            families: ['v4', 'v6'],
            port_restricted: true,
          },
          {
            endpoint_id: 'e1',
            address: 'socks5://10.0.0.6:1080',
            ok: false,
            class: 'proxy_auth',
            handshake_ms: 0,
            error: 'proxy_auth: proxy refused the credentials',
          },
        ],
      },
    ]
    open()
    fireEvent.click(await screen.findByLabelText('Edge A'))
    fireEvent.click(screen.getByRole('button', { name: 'Run test' }))
    const rows = await screen.findAllByTestId('test-result-row')
    expect(rows).toHaveLength(2)
    expect(within(rows[0]).getByText('Works')).toBeTruthy()
    expect(within(rows[0]).getByText('203.0.113.9')).toBeTruthy()
    expect(within(rows[0]).getByText('84 ms')).toBeTruthy()
    expect(within(rows[0]).getByText('IPv4, IPv6')).toBeTruthy()
    expect(within(rows[0]).getByTestId('test-port-restricted')).toBeTruthy()
    expect(within(rows[1]).getByText('Credentials refused')).toBeTruthy()
    expect(within(rows[1]).getByText(/refused the credentials/)).toBeTruthy()
    expect(screen.getByText('Done')).toBeTruthy()
  })

  it('says it is waiting while a sensor has not picked the test up', async () => {
    startTest.mockResolvedValue({ items: [{ command_id: 'c1' }] })
    outcomes = [
      { command_id: 'c1', sensor_id: 's1', sensor_name: 'Edge A', status: 'pending', results: [] },
    ]
    open()
    fireEvent.click(await screen.findByLabelText('Edge A'))
    fireEvent.click(screen.getByRole('button', { name: 'Run test' }))
    expect(await screen.findByText('Waiting for the sensor')).toBeTruthy()
    // Not finished: the button to test again stays off.
    expect((screen.getByRole('button', { name: 'Test again' }) as HTMLButtonElement).disabled).toBe(
      true
    )
  })

  it('explains the one test a minute limit', async () => {
    startTest.mockRejectedValue(new ApiClientError('limited', 'RATE_LIMIT_EXCEEDED', 429))
    open()
    fireEvent.click(await screen.findByLabelText('Edge A'))
    fireEvent.click(screen.getByRole('button', { name: 'Run test' }))
    await waitFor(() => expect(toastError).toHaveBeenCalled())
    expect(String(toastError.mock.calls[0][0])).toMatch(/once a minute/)
  })

  it('says why nothing can be tested when no sensor qualifies', async () => {
    sensors = [sensor({ id: 'old', caps: ['egress.upstream@1'] })]
    open()
    expect(await screen.findByTestId('test-no-sensor')).toBeTruthy()
    expect((screen.getByRole('button', { name: 'Run test' }) as HTMLButtonElement).disabled).toBe(
      true
    )
  })
})

describe('network path of a host direct-only sensor', () => {
  const hostDirect = ['net.confined@1', 'egress.host-direct@1']
  const withDefaultPool = () => {
    pools = [{ ...pool(), enabled: true, is_default: true }]
  }

  beforeEach(() => {
    cleanup()
    assignments = []
  })

  it('shows Direct (set on the sensor host) instead of an upgrade warning', () => {
    withDefaultPool()
    render(
      <TooltipProvider>
        <SensorNetworkPathSection sensorId="s1" capabilities={hostDirect} />
      </TooltipProvider>
    )
    expect(screen.getByText('Direct (set on the sensor host)')).toBeTruthy()
    expect(screen.queryByText('This sensor receives no scan jobs')).toBeNull()
  })

  it('warns that scans wait when a pool is chosen for it', () => {
    withDefaultPool()
    assignments = [{ sensor_id: 's1', mode: 'pool', pool_id: 'p1' }]
    render(
      <TooltipProvider>
        <SensorNetworkPathSection sensorId="s1" capabilities={hostDirect} />
      </TooltipProvider>
    )
    expect(screen.getByText('This sensor receives no scan jobs')).toBeTruthy()
    expect(screen.queryByText('Direct (set on the sensor host)')).toBeNull()
  })

  it('still warns an old sensor without the marker', () => {
    withDefaultPool()
    render(
      <TooltipProvider>
        <SensorNetworkPathSection sensorId="s1" capabilities={['net.confined@1']} />
      </TooltipProvider>
    )
    expect(screen.getByText('This sensor receives no scan jobs')).toBeTruthy()
    expect(screen.queryByText('Direct (set on the sensor host)')).toBeNull()
  })
})
