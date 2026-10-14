import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import SecurityScannersPage from '../page'
import { ScannerImportsView } from '@/features/integrations/components/scanners/scanner-imports-view'
import { TENABLE_CONNECTOR_ENABLED } from '@/features/integrations/config/feature-gates'

/**
 * The Tenable.sc connector is on, as Beta (TENABLE_CONNECTOR_ENABLED, equal to
 * the API's integration.TenableConnectorEnabled): the page renders the
 * connector view. With the gate off, ScannerImportsView offers only what
 * works without the connector: the .nessus import, plus removable paused rows.
 */

const mockUseIntegrations = vi.fn()

vi.mock('@/features/integrations/api/use-integrations-api', () => ({
  useIntegrationsApi: () => mockUseIntegrations(),
  useDeleteIntegrationApi: () => ({ trigger: vi.fn(), isMutating: false }),
  useCreateIntegrationApi: () => ({ trigger: vi.fn(), isMutating: false }),
  useUpdateIntegrationApi: () => ({ trigger: vi.fn(), isMutating: false }),
  useSyncIntegrationApi: () => ({ trigger: vi.fn(), isMutating: false }),
  invalidateIntegrationsCache: vi.fn(),
}))
vi.mock('@/lib/api/sensor-hooks', () => ({
  useAllSensors: () => ({ data: { items: [] }, isLoading: false }),
}))
vi.mock('@/lib/api/scan-coverage-hooks', () => ({
  useScanCoverage: () => ({ data: undefined, isLoading: false }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => children,
  Permission: {
    AssetsWrite: 'assets:write',
    FindingsWrite: 'findings:write',
    IntegrationsManage: 'integrations:manage',
  },
}))

const row = (id: string, provider: string, name: string) => ({
  id,
  name,
  provider,
  category: 'security',
  status: 'connected',
  auth_type: 'api_key',
  config: { execution_mode: 'sensor', engine: 'nessus_pro' },
})

function withRows(rows: ReturnType<typeof row>[]) {
  mockUseIntegrations.mockReturnValue({
    data: { data: rows },
    isLoading: false,
    mutate: vi.fn(),
  })
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('ScannerImportsView (Tenable connector gate off)', () => {
  it('offers no way to connect, edit or set up a Tenable runner, and no coverage panel', () => {
    withRows([row('t1', 'tenable', 'Legacy Tenable')])
    render(<ScannerImportsView />)

    expect(screen.queryByText(/Connect (Scanner|Tenable)/i)).toBeNull()
    expect(screen.queryByTitle('Edit')).toBeNull()
    expect(screen.queryByText(/Runner setup/i)).toBeNull()
    expect(screen.queryByText(/rolling scan freshness/i)).toBeNull()
    expect(screen.getByText(/live Tenable connector is paused/i)).toBeTruthy()
  })

  it('keeps the working .nessus import', () => {
    withRows([])
    render(<ScannerImportsView />)
    expect(screen.getAllByRole('button', { name: /Import \.nessus/i }).length).toBeGreaterThan(0)
  })

  it('lists Tenable rows created before the pause as paused and removable', () => {
    withRows([row('t1', 'tenable', 'Legacy Tenable'), row('d1', 'defectdojo', 'DD')])
    render(<ScannerImportsView />)

    expect(screen.getByText('Legacy Tenable')).toBeTruthy()
    expect(screen.getByText('Paused')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Remove Legacy Tenable' })).toBeTruthy()
    // Non-Tenable security rows are not this page's connectors.
    expect(screen.queryByText('DD')).toBeNull()
  })
})

describe('SecurityScannersPage with the Tenable connector on (Beta)', () => {
  it('is on', () => {
    expect(TENABLE_CONNECTOR_ENABLED).toBe(true)
  })

  it('renders the connector view: Connect Tenable.sc, the Beta badge, no paused-only notice', () => {
    withRows([])
    render(<SecurityScannersPage />)
    expect(screen.getAllByRole('button', { name: /Connect Tenable\.sc/ }).length).toBeGreaterThan(0)
    expect(screen.getByText('Beta')).toBeTruthy()
    expect(screen.queryByText(/live Tenable connector is paused/i)).toBeNull()
  })

  it('still offers the .nessus import and lists older Tenable rows as paused', () => {
    withRows([row('t1', 'tenable', 'Legacy Tenable')])
    render(<SecurityScannersPage />)
    expect(screen.getAllByRole('button', { name: /Import \.nessus/i }).length).toBeGreaterThan(0)
    expect(screen.getByText('Paused Tenable integrations')).toBeTruthy()
    expect(screen.getByText('Legacy Tenable')).toBeTruthy()
  })
})
