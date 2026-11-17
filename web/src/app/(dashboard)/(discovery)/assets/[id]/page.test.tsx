import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

const state = vi.hoisted(() => ({
  tenantLoading: false,
  canRead: true,
  asset: null as unknown,
  assetLoading: false,
  error: undefined as unknown,
  mutate: vi.fn(),
  tab: undefined as string | undefined,
  relationshipsOn: true,
  relatedTotal: 0,
  webItems: [] as unknown[],
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
vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAssetPage: () => ({
    asset: state.asset,
    isLoading: state.assetLoading,
    error: state.error,
    mutate: state.mutate,
  }),
}))
vi.mock('@/features/assets/components/asset-attribute-sources-section', () => ({
  AssetAttributeSourcesSection: () => null,
}))
vi.mock('@/features/assets/components/asset-freshness-section', () => ({
  AssetFreshnessSection: () => null,
}))
vi.mock('@/features/assets/components/asset-coverage-section', () => ({
  AssetCoverageSection: () => null,
}))
vi.mock('@/features/assets/components/asset-attribution-section', () => ({
  AssetAttributionSection: () => null,
}))
vi.mock('@/features/assets/components/asset-lineage-section', () => ({
  AssetLineageSection: () => null,
}))
vi.mock('@/features/assets/components/asset-identity-sections', () => ({
  AssetIdentitySections: () => null,
}))
vi.mock('@/features/assets/components/asset-timeline', () => ({ AssetTimeline: () => null }))
vi.mock('@/features/exploration/components/asset-next-steps', () => ({
  AssetNextSteps: () => null,
}))
vi.mock('@/features/assets/components/classification-badges', () => ({
  ClassificationBadges: () => null,
}))
vi.mock('@/features/assets/components/resolved-ports-section', () => ({
  hasResolvedPorts: (type: string) => type === 'domain' || type === 'subdomain',
  ResolvedPortsSection: () => <section>resolved-ports</section>,
}))
vi.mock('@/features/asset-lifecycle/components/asset-status-badge', () => ({
  AssetStatusBadge: () => null,
}))
vi.mock('@/features/asset-lifecycle/components/asset-liveness-badge', () => ({
  AssetLivenessBadge: () => null,
}))
vi.mock('@/features/scan-windows/components/asset-scan-window-card', () => ({
  AssetScanWindowCard: () => null,
}))
vi.mock('@/features/attack-surface/components/asset-web-evidence-card', () => ({
  AssetWebEvidenceCard: () => null,
}))
vi.mock('@/features/repositories/components/repository-workspace', () => ({
  RepositoryWorkspace: () => null,
}))
vi.mock('@/features/assets/components/asset-owners-tab', () => ({
  AssetOwnersTab: () => <section>owners-tab</section>,
}))
vi.mock('@/features/assets/components/asset-relationships-tab', () => ({
  AssetRelationshipsTab: () => <section>relationships-tab</section>,
}))
vi.mock('@/features/assets/hooks/use-related-assets', () => ({
  useRelatedAssets: (id: string | null) => ({
    total: id ? state.relatedTotal : 0,
    isLoading: false,
  }),
}))
vi.mock('@/features/attack-surface/hooks/use-web-evidence', () => ({
  useWebEvidence: () => ({ items: state.webItems, isLoading: false }),
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: (id: string) => id === 'relationships' && state.relationshipsOn,
}))
vi.mock('@/features/web-surface/components/origin-web-section', () => ({
  isWebOriginType: (type?: string) => type === 'http_service' || type === 'website',
  OriginWebSection: () => <section>origin-web</section>,
}))
vi.mock('@/features/shared/components/settle-group', () => ({
  SettleGroup: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  useSettleSignal: () => {},
}))
vi.mock('@/features/shared/components/detail-sheet-layout', async (orig) => {
  const React = await import('react')
  return {
    ...(await orig<typeof import('@/features/shared/components/detail-sheet-layout')>()),
    useDetailTab: (_param: string, values: readonly string[]) => {
      const [raw, setRaw] = React.useState(state.tab ?? values[0])
      return [values.includes(raw) ? raw : values[0], setRaw]
    },
  }
})

import AssetDetailPage from './page'

beforeEach(() => {
  state.tenantLoading = false
  state.canRead = true
  state.asset = null
  state.assetLoading = false
  state.error = undefined
  state.mutate.mockReset()
  state.tab = undefined
  state.relationshipsOn = true
  state.relatedTotal = 0
  state.webItems = []
})

const BASE = {
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

function tabNames() {
  return screen.getAllByRole('tab').map((el) => el.textContent)
}

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
    state.tab = 'ports'
    const { unmount } = render(<AssetDetailPage />)
    expect(screen.getByText('resolved-ports')).toBeInTheDocument()
    unmount()
    state.asset = { ...base, name: '203.0.113.10', type: 'ip_address' }
    render(<AssetDetailPage />)
    expect(screen.queryByText('resolved-ports')).toBeNull()
    expect(screen.queryByRole('tab', { name: /Ports and services/ })).toBeNull()
  })

  it('follows the detail layout: one h1, properties, the tab strip with counts', () => {
    state.asset = { ...BASE, type: 'subdomain', findingCount: 4, description: 'Front door' }
    state.relatedTotal = 3
    render(<AssetDetailPage />)
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('www.example.com')
    expect(tabNames()).toEqual([
      'Overview',
      'Relationships3',
      'How we found this',
      'Ports and services',
      'Owners and access',
      'Activity',
    ])
    const props = screen.getByRole('group', { name: 'Properties' })
    expect(props).toHaveTextContent('Risk score')
    expect(props).toHaveTextContent('4 open findings')
    expect(props).toHaveTextContent('Front door')
    expect(screen.getByRole('button', { name: 'More actions' })).toBeInTheDocument()
  })

  it('shows the risk score as its value only, and no filler block in Overview', () => {
    state.asset = { ...BASE, type: 'subdomain', riskScore: 82, riskScored: true }
    render(<AssetDetailPage />)
    const props = screen.getByRole('group', { name: 'Properties' })
    expect(props).toHaveTextContent('82')
    expect(props).not.toHaveTextContent('Risk: 82')
    expect(screen.queryByText('Looking for richer details?')).toBeNull()
    // The way to the list stays in More.
    expect(screen.getByRole('button', { name: 'More actions' })).toBeInTheDocument()
  })

  it('opens Owners and access and Relationships on their components', async () => {
    state.asset = { ...BASE, type: 'domain' }
    state.tab = 'owners'
    const { unmount } = render(<AssetDetailPage />)
    expect(await screen.findByText('owners-tab')).toBeInTheDocument()
    unmount()
    state.tab = 'relationships'
    render(<AssetDetailPage />)
    expect(await screen.findByText('relationships-tab')).toBeInTheDocument()
  })

  it('has no Relationships tab when the relationships module is off', () => {
    state.asset = { ...BASE, type: 'domain' }
    state.relationshipsOn = false
    state.tab = 'relationships'
    render(<AssetDetailPage />)
    expect(screen.queryByRole('tab', { name: /Relationships/ })).toBeNull()
    expect(screen.queryByText('relationships-tab')).toBeNull()
    expect(screen.getByRole('tab', { name: /Overview/ })).toHaveAttribute('aria-selected', 'true')
  })

  it('shows the Web tab for a web origin, or when a sensor kept web evidence', () => {
    state.asset = { ...BASE, type: 'http_service' }
    const { unmount } = render(<AssetDetailPage />)
    expect(screen.getByRole('tab', { name: /Web/ })).toBeInTheDocument()
    unmount()
    state.asset = { ...BASE, name: '203.0.113.10', type: 'ip_address' }
    const second = render(<AssetDetailPage />)
    expect(screen.queryByRole('tab', { name: /^Web$/ })).toBeNull()
    second.unmount()
    state.webItems = [{ id: 'w1' }]
    state.tab = 'web'
    render(<AssetDetailPage />)
    expect(screen.getByRole('tab', { name: /Web/ })).toHaveAttribute('aria-selected', 'true')
    expect(screen.queryByText('origin-web')).toBeNull()
  })
})
