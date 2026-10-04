import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import SecurityScannersPage from '../page'
import { TenableConnectorView } from '@/features/integrations/components/scanners/tenable-connector-view'
import { TENABLE_CONNECTOR_ENABLED } from '@/features/integrations/config/feature-gates'

/**
 * Owner decision D-14: the live Tenable connector and rolling coverage are
 * paused (sensor v0.8.0 removed the Tenable runner; the API refuses new
 * Tenable integrations and does not run the coverage scheduler). The page may
 * offer only what works: the .nessus import, plus removable paused rows.
 */

const mockUseIntegrations = vi.fn()

vi.mock('@/features/integrations/api/use-integrations-api', () => ({
  useIntegrationsApi: () => mockUseIntegrations(),
  useDeleteIntegrationApi: () => ({ trigger: vi.fn(), isMutating: false }),
  useCreateIntegrationApi: () => ({ trigger: vi.fn(), isMutating: false }),
  useUpdateIntegrationApi: () => ({ trigger: vi.fn(), isMutating: false }),
  invalidateIntegrationsCache: vi.fn(),
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

describe('SecurityScannersPage while the Tenable connector is paused', () => {
  it('offers no way to connect, edit or set up a Tenable runner, and no coverage panel', () => {
    withRows([row('t1', 'tenable', 'Legacy Tenable')])
    render(<SecurityScannersPage />)

    expect(screen.queryByText(/Connect (Scanner|Tenable)/i)).toBeNull()
    expect(screen.queryByTitle('Edit')).toBeNull()
    expect(screen.queryByText(/Runner setup/i)).toBeNull()
    expect(screen.queryByText(/rolling scan freshness/i)).toBeNull()
    expect(screen.getByText(/live Tenable connector is paused/i)).toBeTruthy()
  })

  it('keeps the working .nessus import', () => {
    withRows([])
    render(<SecurityScannersPage />)
    expect(screen.getAllByRole('button', { name: /Import \.nessus/i }).length).toBeGreaterThan(0)
  })

  it('lists Tenable rows created before the pause as paused and removable', () => {
    withRows([row('t1', 'tenable', 'Legacy Tenable'), row('d1', 'defectdojo', 'DD')])
    render(<SecurityScannersPage />)

    expect(screen.getByText('Legacy Tenable')).toBeTruthy()
    expect(screen.getByText('Paused')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Remove Legacy Tenable' })).toBeTruthy()
    // Non-Tenable security rows are not this page's connectors.
    expect(screen.queryByText('DD')).toBeNull()
  })
})

describe('Tenable connector gate', () => {
  it('is off until the RFC-047 runner ships', () => {
    expect(TENABLE_CONNECTOR_ENABLED).toBe(false)
  })

  it('keeps the connector view, ready to flip back on', () => {
    withRows([])
    render(<TenableConnectorView />)
    expect(screen.getAllByText(/Connect (Scanner|Tenable)/i).length).toBeGreaterThan(0)
  })
})
