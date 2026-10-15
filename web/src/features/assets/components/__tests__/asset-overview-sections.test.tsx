import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  RiskSummarySection,
  OwnershipSection,
  ExposureSection,
  DiscoverySection,
  PropertiesSection,
} from '../asset-overview-sections'
import type { Asset } from '../../types/asset.types'

vi.mock('../../hooks/use-asset-risk', () => ({
  useAssetRisk: () => ({
    isLoading: false,
    error: undefined,
    data: {
      asset_id: 'a1',
      score: 68,
      level: 'high',
      pending: false,
      breakdown: {
        model: 'likelihood_impact',
        score: 68,
        findings_score: 95,
        tiers: [
          { severity: 'critical', count: 5, exploitable: 1, effective: 6, score: 97 },
          { severity: 'high', count: 0, exploitable: 0, effective: 0, score: 0 },
          { severity: 'medium', count: 0, exploitable: 0, effective: 0, score: 0 },
          { severity: 'low', count: 0, exploitable: 0, effective: 0, score: 0 },
        ],
        exposure: 'unknown',
        exposure_factor: 90,
        criticality: 'none',
        effective_criticality: 'none',
        crown_jewel: false,
        criticality_factor: 80,
        control_reduction: 0,
      },
      contributors: [
        {
          finding_id: 'f1',
          title: 'SQL injection in login',
          severity: 'critical',
          in_kev: true,
          exploit_available: false,
          epss_score: 0.62,
        },
      ],
      risk_levels: { critical_min: 80, high_min: 60, medium_min: 40, low_min: 20 },
    },
  }),
}))

const DAY = 86_400_000

function makeAsset(overrides: Partial<Asset> = {}): Asset {
  const now = new Date().toISOString()
  return {
    id: 'a1',
    type: 'repository',
    name: 'github.com/gitleaks/gitleaks',
    criticality: 'high',
    status: 'active',
    scope: 'internal',
    exposure: 'unknown',
    riskScore: 73,
    findingCount: 22,
    findingSeverityCounts: { critical: 0, high: 16, medium: 6, low: 0, info: 0 },
    metadata: {},
    firstSeen: now,
    lastSeen: now,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  } as Asset
}

describe('RiskSummarySection', () => {
  it('shows the risk score, finding count and severity breakdown', () => {
    render(<RiskSummarySection asset={makeAsset()} />)
    expect(screen.getByText(/^73 - /)).toBeInTheDocument()
    expect(screen.getByText('22')).toBeInTheDocument()
    expect(screen.getByText('16')).toBeInTheDocument() // high
    expect(screen.getByText('6')).toBeInTheDocument() // medium
  })

  it('says so when there are no open findings', () => {
    render(<RiskSummarySection asset={makeAsset({ findingCount: 0, findingSeverityCounts: {} })} />)
    expect(screen.getByText('No open findings on this asset.')).toBeInTheDocument()
  })

  it('shows Not yet scored instead of 0 for an asset never scored', () => {
    render(<RiskSummarySection asset={makeAsset({ riskScore: 0, riskScored: false })} />)
    expect(screen.getByText('Not yet scored')).toBeInTheDocument()
    expect(screen.queryByText(/^0 - /)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Why this score?' })).not.toBeInTheDocument()
  })

  it('shows Calculating while the first score is queued', () => {
    render(
      <RiskSummarySection
        asset={makeAsset({ riskScore: 0, riskScored: false, riskScorePending: true })}
      />
    )
    expect(screen.getByText('Calculating…')).toBeInTheDocument()
  })

  it('shows when the score was computed', () => {
    render(
      <RiskSummarySection
        asset={makeAsset({ riskScored: true, riskScoredAt: new Date().toISOString() })}
      />
    )
    expect(screen.getByText('Score updated')).toBeInTheDocument()
  })

  it('explains the score with its factors and the findings that drive it', async () => {
    render(<RiskSummarySection asset={makeAsset({ riskScored: true })} />)
    await userEvent.click(screen.getByRole('button', { name: 'Why this score?' }))
    expect(screen.getByText(/Findings 95 × exposure 90% × criticality 80%/)).toBeInTheDocument()
    expect(screen.getByText('1 exploitable')).toBeInTheDocument()
    const link = screen.getByRole('link', { name: 'SQL injection in login' })
    expect(link).toHaveAttribute('href', '/findings/f1')
    expect(screen.getByText('KEV')).toBeInTheDocument()
    expect(screen.getByText('EPSS 62%')).toBeInTheDocument()
  })

  it('links to the Findings tab', async () => {
    const onViewFindings = vi.fn()
    render(<RiskSummarySection asset={makeAsset()} onViewFindings={onViewFindings} />)
    await userEvent.click(screen.getByRole('button', { name: 'View findings' }))
    expect(onViewFindings).toHaveBeenCalled()
  })
})

describe('OwnershipSection', () => {
  it('shows the primary owner', () => {
    render(
      <OwnershipSection
        asset={makeAsset({
          primaryOwner: { id: 'u1', type: 'user', name: 'Jane Doe', email: 'jane@acme.io' },
        })}
      />
    )
    expect(screen.getByText('Jane Doe')).toBeInTheDocument()
    expect(screen.getByText('jane@acme.io')).toBeInTheDocument()
  })

  it('flags an asset with no owner', () => {
    render(<OwnershipSection asset={makeAsset()} onManageOwners={() => {}} />)
    expect(screen.getByText(/No owner assigned/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Assign owner' })).toBeInTheDocument()
  })
})

describe('ExposureSection', () => {
  it('shows reachability, sensitivity and control-plane status', () => {
    render(
      <ExposureSection
        asset={makeAsset({
          isInternetAccessible: false,
          piiDataExposed: true,
          phiDataExposed: false,
        })}
        isControlPlane
      />
    )
    expect(screen.getByText('Internet-facing').nextSibling).toHaveTextContent('No')
    expect(screen.getByText('PII')).toBeInTheDocument()
    expect(screen.getByText(/other assets depend on it/)).toBeInTheDocument()
  })

  it('reports no sensitive data when both flags are false', () => {
    render(<ExposureSection asset={makeAsset({ piiDataExposed: false, phiDataExposed: false })} />)
    expect(screen.getByText('None flagged')).toBeInTheDocument()
  })

  it('shows the crown-jewel flag from the asset column, not from properties', () => {
    const { unmount } = render(<ExposureSection asset={makeAsset({ isCrownJewel: true })} />)
    expect(screen.getByText('Crown jewel').nextSibling).toHaveTextContent('Yes')
    unmount()
    render(
      <ExposureSection
        asset={makeAsset({ metadata: { is_crown_jewel: true } as unknown as Asset['metadata'] })}
      />
    )
    expect(screen.queryByText('Crown jewel')).not.toBeInTheDocument()
  })
})

describe('DiscoverySection', () => {
  it('shows the source and tool', () => {
    render(
      <DiscoverySection
        asset={makeAsset({ discoverySource: 'sensor', discoveryTool: 'gitleaks' })}
      />
    )
    expect(screen.getByText('Sensor')).toBeInTheDocument()
    expect(screen.getByText('gitleaks')).toBeInTheDocument()
  })

  it('warns when the asset has not been observed for 30+ days', () => {
    const lastSeen = new Date(Date.now() - 78 * DAY).toISOString()
    render(<DiscoverySection asset={makeAsset({ lastSeen })} />)
    expect(screen.getByText(/Not observed for 78 days/)).toBeInTheDocument()
  })

  it('does not warn for a recently seen asset', () => {
    render(<DiscoverySection asset={makeAsset()} />)
    expect(screen.queryByText(/Not observed for/)).not.toBeInTheDocument()
  })
})

describe('PropertiesSection', () => {
  it('renders non-empty properties and skips empty ones', () => {
    render(
      <PropertiesSection
        properties={{
          default_branch: 'main',
          stars: 12,
          archived: false,
          topics: ['go', 'sec'],
          empty: '',
        }}
      />
    )
    expect(screen.getByText('Default branch')).toBeInTheDocument()
    expect(screen.getByText('main')).toBeInTheDocument()
    expect(screen.getByText('go, sec')).toBeInTheDocument()
    expect(screen.queryByText('Empty')).not.toBeInTheDocument()
  })

  it('renders nothing when there are no properties', () => {
    const { container } = render(<PropertiesSection properties={{}} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders from the type schema: one labelled address list linked to the IP assets, the rest under Other', () => {
    render(
      <PropertiesSection
        type="domain"
        properties={{
          ip: '198.51.100.20',
          ip_addresses: ['198.51.100.20', '198.51.100.21'],
          registrar: 'Example Registrar',
          x_vendor_score: 7,
        }}
      />
    )
    expect(screen.getByText('IP addresses')).toBeInTheDocument()
    expect(screen.queryByText('Ip')).not.toBeInTheDocument()
    const link = screen.getByRole('link', { name: '198.51.100.20' })
    expect(link).toHaveAttribute('href', '/assets?types=ip_address&q=198.51.100.20')
    expect(screen.getAllByRole('link')).toHaveLength(2)
    expect(screen.getByText('Registrar')).toBeInTheDocument()
    expect(screen.getByText('Other')).toBeInTheDocument()
    expect(screen.getByText('X vendor score')).toBeInTheDocument()
  })

  it('never links a url property that is not http(s)', () => {
    render(
      <PropertiesSection type="repository" properties={{ canonical_url: 'javascript:alert(1)' }} />
    )
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
  })
})
