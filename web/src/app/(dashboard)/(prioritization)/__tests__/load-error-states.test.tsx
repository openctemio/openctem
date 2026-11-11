/**
 * Business impact and Threat intel: a failed read says so with Retry. It used
 * to render zeros or "no crown jewels yet" (business impact) and an empty
 * overview (threat intel), and a failed CVE lookup always said "not found".
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/business-impact',
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

const dashStats = vi.fn()
const assetStats = vi.fn()
const crown = vi.fn()
const businessUnits = vi.fn()
vi.mock('@/features/dashboard/hooks/use-dashboard-stats', () => ({
  useDashboardStats: () => dashStats(),
}))
vi.mock('@/features/assets/hooks/use-assets', () => ({ useAssetStats: () => assetStats() }))
vi.mock('@/features/crown-jewels/api/use-crown-jewels', () => ({
  useCrownJewels: () => crown(),
}))
vi.mock('@/features/business-units/api/use-business-units', () => ({
  useBusinessUnits: () => businessUnits(),
}))

const threatStats = vi.fn()
const enrich = vi.fn()
vi.mock('@/features/threat-intel/hooks', async (orig) => ({
  ...(await orig<typeof import('@/features/threat-intel/hooks')>()),
  useThreatIntelStats: () => threatStats(),
  enrichCVE: (id: string) => enrich(id),
}))
vi.mock('@/features/threat-intel/components', async (orig) => ({
  ...(await orig<typeof import('@/features/threat-intel/components')>()),
  ThreatActorsPanel: () => null,
}))

import BusinessImpactPage from '../business-impact/page'
import ThreatIntelPage from '../threat-intel/page'

const apiError = new Error('boom: upstream timeout')
const okDash = {
  stats: { findings: { bySeverity: {} } },
  isLoading: false,
  error: undefined,
  mutate: vi.fn(),
}
const okAssets = {
  stats: { total: 4, withFindings: 1, byCriticality: {}, highRiskCount: 0 },
  isLoading: false,
  error: undefined,
  mutate: vi.fn(),
}
const idle = { data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }

beforeEach(() => {
  dashStats.mockReset()
  assetStats.mockReset()
  crown.mockReset()
  businessUnits.mockReset()
  threatStats.mockReset()
  enrich.mockReset()
})

describe('/business-impact', () => {
  it('shows each failed read as an error with Retry, not as zeros or an empty list', () => {
    const retryAssets = vi.fn()
    const retryCrown = vi.fn()
    dashStats.mockReturnValue(okDash)
    assetStats.mockReturnValue({ ...okAssets, error: apiError, mutate: retryAssets })
    crown.mockReturnValue({ ...idle, error: apiError, mutate: retryCrown })
    businessUnits.mockReturnValue({ ...idle, data: { data: [], total: 0 } })
    render(<BusinessImpactPage />)
    expect(screen.getByText(/Failed to load business impact figures/i)).toBeInTheDocument()
    expect(screen.getByText(/Failed to load asset criticality/i)).toBeInTheDocument()
    expect(screen.getByText(/Failed to load crown jewels/i)).toBeInTheDocument()
    expect(screen.queryByText(/No crown jewels yet/i)).not.toBeInTheDocument()
    const retries = screen.getAllByRole('button', { name: /retry/i })
    expect(retries).toHaveLength(3)
    retries.forEach((b) => fireEvent.click(b))
    expect(retryCrown).toHaveBeenCalledTimes(1)
    expect(retryAssets).toHaveBeenCalled()
  })
})

describe('/threat-intel', () => {
  const stats = {
    epssStats: undefined,
    kevStats: undefined,
    syncStatuses: [],
    isLoading: false,
    mutate: vi.fn(),
  }

  it('shows a failed overview read as an error with Retry', () => {
    const retry = vi.fn()
    threatStats.mockReturnValue({ ...stats, error: apiError, mutate: retry })
    render(<ThreatIntelPage />)
    expect(screen.getByText(/Failed to load threat intelligence/i)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(retry).toHaveBeenCalledTimes(1)
  })

  async function lookup(rejection: unknown) {
    threatStats.mockReturnValue({ ...stats, error: undefined })
    enrich.mockRejectedValue(rejection)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    render(<ThreatIntelPage />)
    fireEvent.mouseDown(screen.getByRole('tab', { name: /lookup/i }))
    fireEvent.click(screen.getByRole('tab', { name: /lookup/i }))
    fireEvent.change(screen.getByLabelText(/CVE ID/i), { target: { value: 'CVE-2021-44228' } })
    fireEvent.click(screen.getByRole('button', { name: /^lookup$/i }))
  }

  it('shows a failed CVE lookup as an error with Retry, not as "not found"', async () => {
    await lookup(Object.assign(new Error('upstream 503'), { statusCode: 503 }))
    await waitFor(() =>
      expect(screen.getByText(/Failed to load the CVE lookup/i)).toBeInTheDocument()
    )
    expect(screen.queryByText(/CVE not found/i)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    await waitFor(() => expect(enrich).toHaveBeenCalledTimes(2))
  })

  it('keeps "not found" for a 404, which is the answer', async () => {
    await lookup(Object.assign(new Error('missing'), { statusCode: 404 }))
    await waitFor(() => expect(screen.getByText(/CVE not found/i)).toBeInTheDocument())
    expect(screen.queryByText(/Failed to load/i)).not.toBeInTheDocument()
  })
})
