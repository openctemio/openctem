import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

const state = vi.hoisted(() => ({
  tenantLoading: false,
  canRead: true,
  asset: null as unknown,
  assetLoading: false,
  error: undefined as unknown,
  mutate: vi.fn(),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), back: vi.fn() }),
  useParams: () => ({ id: 'a1' }),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
  useBreadcrumbTitle: () => {},
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ isLoading: state.tenantLoading }),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => state.canRead }),
}))
vi.mock('@/features/assets', () => ({
  useAssetPage: () => ({
    asset: state.asset,
    isLoading: state.assetLoading,
    error: state.error,
    mutate: state.mutate,
  }),
  AssetAttributeSourcesSection: () => null,
  AssetFreshnessSection: () => null,
  AssetCoverageSection: () => null,
  AssetAttributionSection: () => null,
  AssetLineageSection: () => null,
  AssetIdentitySections: () => null,
  AssetTimeline: () => null,
}))
vi.mock('@/features/assets/components/classification-badges', () => ({
  ClassificationBadges: () => null,
}))
vi.mock('@/features/assets/components/resolved-ports-section', () => ({
  hasResolvedPorts: (type: string) => type === 'domain' || type === 'subdomain',
  ResolvedPortsSection: () => <section>resolved-ports</section>,
}))
vi.mock('@/features/asset-lifecycle', () => ({ AssetStatusBadge: () => null }))
vi.mock('@/features/scan-windows', () => ({ AssetScanWindowCard: () => null }))
vi.mock('@/features/attack-surface', () => ({ AssetWebEvidenceCard: () => null }))
vi.mock('@/features/repositories/components/repository-workspace', () => ({
  RepositoryWorkspace: () => null,
}))

import AssetDetailPage from './page'

beforeEach(() => {
  state.tenantLoading = false
  state.canRead = true
  state.asset = null
  state.assetLoading = false
  state.error = undefined
  state.mutate.mockReset()
})

describe('/assets/[id]', () => {
  it('shows a skeleton, not "not found", while the tenant loads', () => {
    state.tenantLoading = true
    render(<AssetDetailPage />)
    expect(screen.getByRole('status')).toBeInTheDocument()
    expect(screen.queryByText('Asset not found')).toBeNull()
  })

  it('says so without assets:read instead of "not found"', () => {
    state.canRead = false
    render(<AssetDetailPage />)
    expect(screen.getByText('You do not have access to assets')).toBeInTheDocument()
    expect(screen.queryByText('Asset not found')).toBeNull()
  })

  it('a server error offers retry and is not "not found"', () => {
    state.error = Object.assign(new Error('boom'), { statusCode: 500 })
    render(<AssetDetailPage />)
    expect(screen.queryByText('Asset not found')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(state.mutate).toHaveBeenCalled()
  })

  it('a 404 reads as not found', () => {
    state.error = Object.assign(new Error('nope'), { statusCode: 404 })
    render(<AssetDetailPage />)
    expect(screen.getByText('Asset not found')).toBeInTheDocument()
  })

  it('an unscored asset does not print 0/100 and the type has a real label', () => {
    state.asset = {
      id: 'a1',
      name: 'portal',
      type: 'http_service',
      status: 'active',
      riskScore: 0,
      riskScored: false,
      findingCount: 0,
      scope: 'external',
      exposure: 'public',
      criticality: 'high',
      tags: [],
    }
    render(<AssetDetailPage />)
    expect(screen.queryByText(/0\/100/)).toBeNull()
    expect(screen.queryByText(/http_service/)).toBeNull()
    expect(screen.getByText(/Not yet scored/i)).toBeInTheDocument()
  })

  it('a domain shows the ports of its resolved addresses; an address does not', () => {
    const base = {
      id: 'a1',
      name: 'www.example.com',
      status: 'active',
      riskScore: 0,
      riskScored: false,
      findingCount: 0,
      scope: 'external',
      exposure: 'public',
      criticality: 'high',
      tags: [],
    }
    state.asset = { ...base, type: 'subdomain' }
    const { unmount } = render(<AssetDetailPage />)
    expect(screen.getByText('resolved-ports')).toBeInTheDocument()
    unmount()
    state.asset = { ...base, name: '203.0.113.10', type: 'ip_address' }
    render(<AssetDetailPage />)
    expect(screen.queryByText('resolved-ports')).toBeNull()
  })
})
