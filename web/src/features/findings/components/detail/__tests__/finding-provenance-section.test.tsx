import { describe, expect, it } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import type { FindingDetail } from '../../../types'
import { FindingProvenanceSection } from '../finding-provenance-section'

function finding(over: Partial<FindingDetail> = {}): FindingDetail {
  return {
    id: 'f1',
    title: 'Django SQL injection',
    description: '',
    severity: 'critical',
    status: 'new',
    source: 'sca',
    toolName: 'trivy',
    assets: [
      { id: 'a1', type: 'repository', name: 'gitlab.com/acme/django-nv', criticality: 'medium' },
    ],
    evidence: [],
    remediation: { description: '', steps: [], references: [], progress: 0 },
    relatedFindings: [],
    discoveredAt: '2026-10-15T00:00:00Z',
    createdAt: '2026-10-15T00:00:00Z',
    updatedAt: '2026-10-15T00:00:00Z',
    activities: [],
    provenance: {
      firstDetectedBranch: 'main',
      firstDetectedCommit: '67da69d5701fb12f',
      lastSeenBranch: 'main',
      lastSeenCommit: '67da69d5701fb12f',
      branches: [
        {
          name: 'main',
          isDefault: true,
          status: 'open',
          firstSeenAt: '2026-10-15T02:59:57Z',
          lastSeenAt: '2026-10-15T03:00:57Z',
          firstCommit: '67da69d5701fb12f',
          lastCommit: '0dacaf6288a9d5d7',
        },
        {
          name: 'feat/bump-requests',
          isDefault: false,
          status: 'auto_fixed',
          firstSeenAt: '2026-10-15T03:00:27Z',
          lastSeenAt: '2026-10-15T03:00:27Z',
          firstCommit: 'a481d52bffda57b7',
          lastCommit: 'a481d52bffda57b7',
        },
      ],
      runs: [],
      ...over.provenance,
    },
    ...over,
  } as FindingDetail
}

describe('FindingProvenanceSection', () => {
  it('shows first and last sighting with commit links and every branch', () => {
    render(<FindingProvenanceSection finding={finding()} />)
    const s = screen.getByRole('region', { name: 'Provenance' })
    expect(s).toHaveTextContent('First seenmain@67da69d5')
    // Last seen comes from the newest branch occurrence, not the stale column.
    expect(s).toHaveTextContent('Last seenmain@0dacaf62')
    expect(s).toHaveTextContent('On 2 branches')
    expect(s).toHaveTextContent('fixed here')
    expect(within(s).getAllByRole('link', { name: '@67da69d5' })[0]).toHaveAttribute(
      'href',
      'https://gitlab.com/acme/django-nv/-/commit/67da69d5701fb12f'
    )
  })

  it('names the first pipeline and merge request, and links only http(s)', () => {
    render(
      <FindingProvenanceSection
        finding={finding({
          provenance: {
            branches: [],
            runs: [
              {
                id: 'r2',
                provider: 'gitlab',
                externalRunId: '2101000023',
                pipelineUrl: 'javascript:alert(1)',
                branch: 'main',
                isDefaultBranch: true,
                createdAt: '2026-10-15T03:00:57Z',
              },
            ],
            firstRun: {
              id: 'r1',
              provider: 'gitlab',
              externalRunId: '2101000021',
              pipelineUrl: 'https://gitlab.com/acme/django-nv/-/pipelines/2101000021',
              branch: 'main',
              commitSha: '67da69d5701fb12f',
              pullRequest: '12',
              isDefaultBranch: true,
              createdAt: '2026-10-15T02:59:57Z',
            },
          },
        })}
      />
    )
    const s = screen.getByRole('region', { name: 'Provenance' })
    expect(within(s).getByRole('link', { name: /Pipeline #2101000021/ })).toHaveAttribute(
      'href',
      'https://gitlab.com/acme/django-nv/-/pipelines/2101000021'
    )
    expect(s).toHaveTextContent('MR !12')
    expect(within(s).queryByRole('link', { name: /Pipeline #2101000023/ })).toBeNull()
    expect(s).toHaveTextContent('Pipeline #2101000023')
  })

  it('renders nothing without provenance', () => {
    const { container } = render(
      <FindingProvenanceSection finding={finding({ provenance: undefined })} />
    )
    expect(container).toBeEmptyDOMElement()
  })
})
