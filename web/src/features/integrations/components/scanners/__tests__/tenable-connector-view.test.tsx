import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'

import { TenableConnectorView } from '../tenable-connector-view'

/**
 * The Tenable.sc sensor connector page (api RFC-047), rendered while
 * TENABLE_CONNECTOR_ENABLED: connectors with their sync status, cursor and
 * the allow-list the sensor reported; Sync now for integrations managers
 * only; the coverage panel with Tenable.sc's license numbers.
 */

const mockIntegrations = vi.fn()
const mockSync = vi.fn()
const mockCreate = vi.fn()
let canManage = true

vi.mock('@/features/integrations/api/use-integrations-api', () => ({
  useIntegrationsApi: () => mockIntegrations(),
  useDeleteIntegrationApi: () => ({ trigger: vi.fn(), isMutating: false }),
  useCreateIntegrationApi: () => ({ trigger: mockCreate, isMutating: false }),
  useUpdateIntegrationApi: () => ({ trigger: vi.fn(), isMutating: false }),
  useSyncIntegrationApi: () => ({ trigger: mockSync, isMutating: false }),
  invalidateIntegrationsCache: vi.fn(),
}))
vi.mock('@/lib/api/sensor-hooks', () => ({
  useAllSensors: () => ({
    data: {
      items: [
        {
          id: 's1',
          name: 'dc-sensor',
          status: 'active',
          reported: { tools: [{ name: 'tenable_sc', installed: true }] },
        },
        { id: 'p1', name: 'shared', status: 'active', is_platform_sensor: true },
      ],
    },
    isLoading: false,
  }),
}))
vi.mock('@/lib/api/scan-coverage-hooks', () => ({
  useScanCoverage: () => ({
    data: {
      window_days: 30,
      total_scannable: 200,
      covered_in_window: 150,
      never_scanned: 20,
      stale: 30,
      critical_never_scanned: 0,
      critical_uncovered: 0,
      coverage_percent: 75,
    },
    isLoading: false,
  }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children, permission }: { children: React.ReactNode; permission: string | string[] }) => {
    const needs = Array.isArray(permission) ? permission : [permission]
    return needs.includes('integrations:manage') && !canManage ? null : children
  },
  Permission: {
    AssetsWrite: 'assets:write',
    FindingsWrite: 'findings:write',
    IntegrationsManage: 'integrations:manage',
  },
}))

const connector = (over: Record<string, unknown> = {}, sync: Record<string, unknown> = {}) => ({
  id: 'i1',
  name: 'Tenable.sc prod',
  provider: 'tenable',
  category: 'security',
  status: 'connected',
  auth_type: 'api_key',
  next_sync_at: '2026-10-04T18:00:00Z',
  config: {
    engine: 'tenable_sc',
    execution_mode: 'sensor',
    sensor_id: 's1',
    instance: 'sc-prod',
    coverage_enabled: true,
    coverage_policy_id: 1000003,
    coverage_repository_id: 5,
    safety_margin: 10,
    ...over,
  },
  metadata: {
    tenable_sync: {
      last_successful_sync: '2026-10-04T10:00:00Z',
      last_full_sync: '2026-10-01T10:00:00Z',
      last_outcome: 'completed',
      tenable_version: '6.4.0',
      licensed_ips: 1000,
      active_ips: 420,
      hosts: 120,
      open: 80,
      mitigated: 3,
      plugins: 40,
      catalog: {
        repositories: [{ id: 5, name: 'Datacenter' }],
        policies: [{ id: 1000003, name: 'Basic Network Scan' }],
        scan_repositories: [{ id: 5, name: 'Datacenter' }],
      },
      ...sync,
    },
  },
})

function withRows(rows: unknown[]) {
  mockIntegrations.mockReturnValue({ data: { data: rows }, isLoading: false, mutate: vi.fn() })
}

beforeEach(() => {
  vi.clearAllMocks()
  canManage = true
})

describe('TenableConnectorView', () => {
  it('shows a connector with its sensor, cursor, counts and the allow-list the sensor reported', () => {
    withRows([connector()])
    render(<TenableConnectorView />)

    expect(screen.getByText('Tenable.sc prod')).toBeTruthy()
    expect(screen.getByText(/Sensor dc-sensor · instance sc-prod · Tenable.sc 6.4.0/)).toBeTruthy()
    expect(screen.getByText('Completed')).toBeTruthy()
    expect(screen.getByText('80')).toBeTruthy()
    expect(screen.getByText('Basic Network Scan')).toBeTruthy()
    expect(screen.getAllByText('Datacenter').length).toBe(2)
  })

  it('queues a sync for an integrations manager', async () => {
    withRows([connector()])
    render(<TenableConnectorView />)
    fireEvent.click(screen.getByRole('button', { name: /Sync now/ }))
    await waitFor(() => expect(mockSync).toHaveBeenCalledTimes(1))
  })

  it('offers no Sync now, Edit, Remove or Connect without integrations:manage', () => {
    canManage = false
    withRows([connector()])
    render(<TenableConnectorView />)
    expect(screen.queryByRole('button', { name: /Sync now/ })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Edit connector' })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Remove connector' })).toBeNull()
    expect(screen.queryByRole('button', { name: /Connect Tenable.sc/ })).toBeNull()
  })

  it('disables Sync now while a sync is running', () => {
    withRows([connector({}, { open_command_id: 'c1', open_mode: 'incremental' })])
    render(<TenableConnectorView />)
    expect(screen.getByText('Sync running')).toBeTruthy()
    expect((screen.getByRole('button', { name: /Sync now/ }) as HTMLButtonElement).disabled).toBe(
      true
    )
  })

  it('shows the sync error', () => {
    withRows([
      { ...connector(), sync_error: 'credentials_rejected: Tenable.sc refused the API keys' },
    ])
    render(<TenableConnectorView />)
    expect(screen.getByText(/refused the API keys/)).toBeTruthy()
  })

  it('shows the license, the batch state and the next batch in the coverage panel', () => {
    withRows([connector({}, { coverage_command_id: 'b1' })])
    render(<TenableConnectorView />)
    const panel = screen.getByRole('region', { name: 'Coverage' })
    expect(within(panel).getByText('420 / 1000')).toBeTruthy()
    expect(
      within(panel).getByRole('meter', { name: '420 of 1000 licensed IPs in use' })
    ).toBeTruthy()
    expect(within(panel).getByText('Running')).toBeTruthy()
    expect(within(panel).getByText('After the current batch')).toBeTruthy()
    expect(within(panel).getByText('75.0%')).toBeTruthy()
  })

  it('computes the next batch from Tenable.sc numbers, and says when there is not enough data', () => {
    withRows([connector()])
    const { unmount } = render(<TenableConnectorView />)
    expect(screen.getByText('570 IPs')).toBeTruthy() // 1000 - 420 - 10
    unmount()

    withRows([connector({}, { licensed_ips: 0, active_ips: 0 })])
    render(<TenableConnectorView />)
    expect(screen.getAllByText('Not enough data').length).toBeGreaterThan(0)
  })

  it('lists older Tenable rows as paused, not as connectors', () => {
    withRows([
      connector(),
      {
        id: 'old',
        name: 'Old Nessus',
        provider: 'tenable',
        category: 'security',
        status: 'pending',
        auth_type: 'api_key',
        config: { engine: 'nessus_pro', execution_mode: 'sensor' },
      },
    ])
    render(<TenableConnectorView />)
    expect(screen.getByText('Paused Tenable integrations')).toBeTruthy()
    expect(screen.getByText('Old Nessus')).toBeTruthy()
  })

  it('creates a connector in sensor mode with no credentials, on one of the tenant sensors', async () => {
    withRows([])
    render(<TenableConnectorView />)
    fireEvent.click(screen.getAllByRole('button', { name: /Connect Tenable.sc/ })[0])
    // The platform sensor is not offered.
    expect(screen.queryByText(/shared/)).toBeNull()
    // Without a sensor the form refuses.
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }))
    expect(mockCreate).not.toHaveBeenCalled()
  })
})
