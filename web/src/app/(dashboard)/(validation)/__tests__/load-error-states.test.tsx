/**
 * Validation hub, ATT&CK coverage, pentest campaigns and attack simulation: a
 * failed read says so with Retry. The hub used to show a dash with no
 * explanation, and ATT&CK coverage drew an empty heatmap (0% covered).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/validation',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'Acme', slug: 'acme', role: 'owner' } }),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useHasPermission: () => true,
  usePermissions: () => ({ can: () => true, canAny: () => true, canAll: () => true }),
}))
vi.mock('@/context/permission-provider', async (orig) => ({
  ...(await orig<typeof import('@/context/permission-provider')>()),
  usePermissions: () => ({ hasPermission: () => true, can: () => true }),
  useRolePermissions: () => ({ isAdmin: true }),
}))
vi.mock('@/context/brand-provider', async (orig) => ({
  ...(await orig<typeof import('@/context/brand-provider')>()),
  useDocsHref: () => (p: string) => p,
}))

const coverage = vi.fn()
vi.mock('@/features/validation/api/use-validation-coverage', () => ({
  useValidationCoverage: () => coverage(),
}))
vi.mock('@/features/findings/api/use-findings-count', () => ({
  useFindingsCount: () => 0,
}))
vi.mock('@/features/closure-review/api', () => ({ useReadyToCloseCount: () => 0 }))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => true,
  useTenantModules: () => ({
    moduleIds: ['pentest', 'attack_simulation'],
    notEntitledModuleIds: [],
    isLoading: false,
  }),
}))

const pentestFindings = vi.fn()
const campaigns = vi.fn()
const simulations = vi.fn()
vi.mock('@/features/pentest/api/use-pentest-api', async (orig) => ({
  ...(await orig<typeof import('@/features/pentest/api/use-pentest-api')>()),
  useAllPentestFindings: () => pentestFindings(),
  useAdaptedPentestFindingPage: () => ({ data: undefined }),
  useAdaptedCampaigns: () => campaigns(),
}))
vi.mock('@/features/simulation/api/use-simulation-api', async (orig) => ({
  ...(await orig<typeof import('@/features/simulation/api/use-simulation-api')>()),
  useSimulations: () => simulations(),
  useRunSimulation: () => ({ trigger: vi.fn(), isMutating: false }),
}))
vi.mock('@/features/pentest/components/campaign-create-wizard', () => ({
  CampaignCreateWizard: () => null,
}))

import ValidationPage from '../validation/page'
import AttackCoveragePage from '../validation/attack-coverage/page'
import CampaignsPage from '../pentest/campaigns/page'
import AttackSimulationPage from '../attack-simulation/page'

const apiError = new Error('boom: upstream timeout')
const idle = { data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }

beforeEach(() => {
  coverage.mockReset()
  pentestFindings.mockReset()
  campaigns.mockReset()
  simulations.mockReset()
})

describe('/validation', () => {
  it('names a failed coverage read and offers Retry instead of a bare dash', () => {
    const retry = vi.fn()
    coverage.mockReturnValue({ ...idle, error: apiError, mutate: retry })
    campaigns.mockReturnValue(idle)
    render(<ValidationPage />)
    expect(screen.getByText(/Failed to load validation coverage/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(retry).toHaveBeenCalledTimes(1)
  })
})

describe('/validation/attack-coverage', () => {
  it('shows a failed read as an error with Retry for both sources, not an empty heatmap', () => {
    const retryFindings = vi.fn()
    const retrySims = vi.fn()
    pentestFindings.mockReturnValue({ ...idle, error: apiError, mutate: retryFindings })
    simulations.mockReturnValue({ ...idle, data: { data: [], total: 0 }, mutate: retrySims })
    render(<AttackCoveragePage />)
    expect(screen.getByText(/Failed to load ATT&CK coverage/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(retryFindings).toHaveBeenCalledTimes(1)
    expect(retrySims).toHaveBeenCalledTimes(1)
  })

  it('also fails when only the simulations read fails', () => {
    pentestFindings.mockReturnValue({ ...idle, data: { data: [], total: 0 } })
    simulations.mockReturnValue({ ...idle, error: apiError })
    render(<AttackCoveragePage />)
    expect(screen.getByText(/Failed to load ATT&CK coverage/i)).toBeInTheDocument()
  })
})

describe('/pentest/campaigns', () => {
  it('shows a failed read as an error with Retry, not "No campaigns yet"', () => {
    const retry = vi.fn()
    campaigns.mockReturnValue({ ...idle, error: apiError, mutate: retry })
    render(<CampaignsPage />)
    expect(screen.getByText(/Failed to load campaigns/i)).toBeInTheDocument()
    expect(screen.queryByText(/No campaigns/i)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(retry).toHaveBeenCalledTimes(1)
  })
})

describe('/attack-simulation', () => {
  it('shows a failed read as an error with Retry, not "No simulations yet"', () => {
    const retry = vi.fn()
    simulations.mockReturnValue({ ...idle, error: apiError, mutate: retry })
    render(<AttackSimulationPage />)
    expect(screen.getByText(/Failed to load simulations/i)).toBeInTheDocument()
    expect(screen.queryByText(/No simulations/i)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(retry).toHaveBeenCalledTimes(1)
  })
})
