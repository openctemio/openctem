import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { FindingDetail } from '../../../types'
import { FindingIntelSection } from '../finding-intel-section'

function finding(over: Partial<FindingDetail> = {}): FindingDetail {
  return {
    id: 'f1',
    title: 'Django SQL injection',
    description: '',
    severity: 'critical',
    status: 'new',
    source: 'sca',
    assets: [],
    evidence: [],
    remediation: { description: '', steps: [], references: [], progress: 0 },
    relatedFindings: [],
    discoveredAt: '2026-10-15T00:00:00Z',
    createdAt: '2026-10-15T00:00:00Z',
    updatedAt: '2026-10-15T00:00:00Z',
    activities: [],
    cve: 'CVE-2025-64459',
    cwe: 'CWE-89',
    cvss: 9.1,
    epssScore: 0.19257,
    epssPercentile: 97.3,
    isInKev: false,
    intel: {
      references: ['https://github.com/advisories/GHSA-frmv-pr5f-9mcr', 'javascript:alert(1)'],
      epssDate: '2026-10-15',
      publishedAt: '2025-11-05T15:15:41Z',
    },
    ...over,
  } as FindingDetail
}

describe('FindingIntelSection', () => {
  it('states KEV, EPSS with its date and safe references', () => {
    render(<FindingIntelSection finding={finding()} />)
    const s = screen.getByRole('region', { name: 'Intelligence' })
    expect(s).toHaveTextContent('CISA KEVNot listed')
    expect(s).toHaveTextContent('19.3% · 97th percentile · as of Oct 15, 2026')
    expect(s).toHaveTextContent('PublishedNov 5, 2025')
    const links = screen.getAllByRole('link')
    expect(links.every((a) => /^https:\/\//.test(a.getAttribute('href') ?? ''))).toBe(true)
    expect(links.every((a) => a.getAttribute('rel')?.includes('noopener'))).toBe(true)
  })

  it('names the KEV date when the CVE is known exploited', () => {
    render(
      <FindingIntelSection
        finding={finding({
          isInKev: true,
          kevDueDate: '2026-01-23',
          intel: { references: [], kevDateAdded: '2026-01-02', kevRansomware: true },
        })}
      />
    )
    expect(screen.getByRole('region', { name: 'Intelligence' })).toHaveTextContent(
      'Known exploited since Jan 2, 2026 · due Jan 23, 2026 · used in ransomware'
    )
  })

  it('renders nothing for a finding with no vulnerability facts', () => {
    const { container } = render(
      <FindingIntelSection
        finding={finding({
          cve: undefined,
          cwe: undefined,
          cvss: undefined,
          epssScore: undefined,
          intel: undefined,
        })}
      />
    )
    expect(container).toBeEmptyDOMElement()
  })
})
