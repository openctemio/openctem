import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import type { FindingDetail } from '../../../types'

// The score breakdown is fetched only when "How this was scored" is opened.
const explain = vi.hoisted(() => vi.fn(() => ({ explanation: null, isLoading: false })))
vi.mock('../../../api/use-finding-priority-explanation', () => ({
  useFindingPriorityExplanation: explain,
}))
// SLA windows come from the asset's effective policy on the API.
const slaPolicy = vi.hoisted(() =>
  vi.fn((_assetId?: string | null) => ({
    data: { p0_days: 3, p1_days: 9, p2_days: 20, p3_days: 40 },
  }))
)
vi.mock('@/features/sla/api/use-sla-policies-api', () => ({
  useEffectiveSlaPolicy: slaPolicy,
}))
vi.mock('@/lib/clipboard', () => ({ copyToClipboard: vi.fn(async () => true) }))

const { FindingWhyItMatters } = await import('../finding-why-it-matters')
const { FindingFixCard } = await import('../finding-fix-card')

function finding(over: Partial<FindingDetail> = {}): FindingDetail {
  return {
    id: 'f1',
    title: 'cross-spawn ReDoS vulnerability',
    description: '',
    severity: 'high',
    status: 'new',
    source: 'sca',
    assets: [
      {
        id: 'a1',
        type: 'website',
        name: 'demo-web-storefront',
        criticality: 'critical',
        exposure: 'public',
        isInternetAccessible: true,
      },
    ],
    evidence: [],
    remediation: { description: '', steps: [], references: [], progress: 0 },
    relatedFindings: [],
    discoveredAt: '2026-05-07T00:00:00Z',
    createdAt: '2026-05-07T00:00:00Z',
    updatedAt: '2026-05-07T00:00:00Z',
    activities: [],
    cve: 'CVE-2024-21538',
    priorityClass: 'P1',
    priorityClassReason: 'high severity, reachable, no compensating controls',
    reachableFromCount: 1,
    isInternetAccessible: true,
    epssScore: 0.00868,
    epssPercentile: 57.276,
    component: {
      name: 'cross-spawn',
      version: '7.0.3',
      ecosystem: 'npm',
      fixedIn: '7.0.5',
      dependencyType: 'transitive',
      manifestFile: 'package.json',
    },
    advisory: {
      cveId: 'CVE-2024-21538',
      exploitAvailable: false,
      exploitMaturity: 'none',
      fixedVersions: ['7.0.5', '6.0.6'],
      references: [],
    },
    ...over,
  }
}

describe('FindingWhyItMatters', () => {
  it('leads with the P-class and the reason, then the grouped signals', () => {
    render(<FindingWhyItMatters finding={finding()} />)
    const panel = screen.getByRole('region', { name: 'Why it matters' })
    expect(within(panel).getByText('P1')).toBeInTheDocument()
    // The P1 window of the finding's asset, as the API reports it.
    expect(within(panel).getByText('fix within 9 days')).toBeInTheDocument()
    expect(slaPolicy).toHaveBeenCalledWith('a1')
    expect(
      within(panel).getByText('High severity, reachable, no compensating controls.')
    ).toBeInTheDocument()
    expect(within(panel).getByRole('list', { name: 'Exploitation' })).toHaveTextContent(
      'No known exploit'
    )
    expect(within(panel).getByRole('list', { name: 'Exposure' })).toHaveTextContent(
      'Internet-facing'
    )
    expect(within(panel).getByRole('list', { name: 'Business impact' })).toHaveTextContent(
      'Critical asset'
    )
    // Each chip says which way it pushes, for screen readers.
    expect(within(panel).getByText('Internet-facing').parentElement).toHaveTextContent(
      'raises priority'
    )
  })

  it('explains an attribution cap and links to verify ownership', () => {
    const assetId = '0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b'
    render(
      <FindingWhyItMatters
        finding={finding({
          priorityClass: 'P2',
          priorityClassReason:
            'KEV-listed, reachable · capped at P2 until ownership is confirmed (was P0; asset attribution: needs_review)',
          assets: [{ id: assetId, type: 'domain', name: 'api.acme.io' }],
        })}
      />
    )
    const note = screen.getByRole('note', { name: 'Ownership not confirmed' })
    expect(note).toHaveTextContent('held at P2')
    expect(within(note).getByRole('link', { name: 'Verify ownership' })).toHaveAttribute(
      'href',
      `/assets/${assetId}`
    )
  })

  it('shows no ownership note for an uncapped finding', () => {
    render(<FindingWhyItMatters finding={finding()} />)
    expect(screen.queryByRole('note', { name: 'Ownership not confirmed' })).toBeNull()
  })

  it('does not fetch the score breakdown until it is opened', () => {
    explain.mockClear()
    render(<FindingWhyItMatters finding={finding()} />)
    expect(explain).not.toHaveBeenCalled()
    expect(screen.getByText('How this was scored')).toBeInTheDocument()
  })

  it('renders nothing without a priority or any signal', () => {
    const { container } = render(
      <FindingWhyItMatters
        finding={finding({
          priorityClass: undefined,
          priorityClassReason: undefined,
          reachableFromCount: 0,
          isInternetAccessible: false,
          epssScore: undefined,
          advisory: undefined,
          assets: [],
        })}
      />
    )
    expect(container).toBeEmptyDOMElement()
  })
})

describe('FindingFixCard', () => {
  it('names the upgrade and gives the npm override for a transitive package', () => {
    render(<FindingFixCard finding={finding()} />)
    const card = screen.getByRole('region', { name: 'Fix' })
    expect(card).toHaveTextContent('Upgrade cross-spawn7.0.37.0.5')
    expect(card).toHaveTextContent('Transitive dependency · in package.json · npm')
    expect(card).toHaveTextContent('"cross-spawn": "^7.0.5"')
    expect(card).toHaveTextContent('Also fixed in 6.0.6')
    expect(within(card).getByRole('button', { name: 'Copy package.json overrides snippet' }))
  })

  it('compact: the action line only', () => {
    render(<FindingFixCard finding={finding()} compact />)
    expect(screen.queryByText(/overrides/)).not.toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Fix' })).toHaveTextContent('Upgrade cross-spawn')
  })

  it('renders nothing when there is no concrete fix', () => {
    const { container } = render(
      <FindingFixCard
        finding={finding({ source: 'sast', component: undefined, advisory: undefined })}
      />
    )
    expect(container).toBeEmptyDOMElement()
  })
})
