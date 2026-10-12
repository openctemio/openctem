import { describe, it, expect, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import type { FindingDetail } from '../../../types'

vi.mock('@/lib/clipboard', () => ({ copyToClipboard: vi.fn(async () => true) }))
vi.mock('../../../api/use-finding-groups', () => ({
  useRelatedCVEs: (cve: string | null) => ({
    data: cve
      ? {
          source_cve: cve,
          related_cves: [
            { cve_id: 'CVE-2014-0346', title: 'x', severity: 'high', finding_count: 2 },
            { cve_id: 'CVE-2016-2107', title: 'y', severity: 'high', finding_count: 1 },
          ],
        }
      : undefined,
  }),
}))

const { OverviewTab } = await import('../overview-tab')

const RLO = String.fromCodePoint(0x202e)

function finding(over: Partial<FindingDetail> = {}): FindingDetail {
  return {
    id: 'f1',
    title: 'OpenSSL Heartbleed',
    description: 'A memory disclosure.',
    severity: 'critical',
    status: 'new',
    source: 'va',
    assets: [],
    evidence: [],
    remediation: { description: '', steps: [], references: [], progress: 0 },
    relatedFindings: [],
    discoveredAt: '2026-05-07T00:00:00Z',
    createdAt: '2026-05-07T00:00:00Z',
    updatedAt: '2026-05-07T00:00:00Z',
    activities: [],
    cve: 'CVE-2014-0160',
    cvss: 7.5,
    cvssVector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    scannerFacts: {
      family: 'General',
      vprScore: 8.9,
      cvssVersion: '3.x',
      cvssV2Vector: 'AV:N/AC:L/Au:N/C:P/I:N/A:N',
      cvssV3Vector: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
      cveIds: ['CVE-2014-0160', 'CVE-2014-0346', 'not-a-cve<script>'],
      patchPublishedAt: '2014-04-07T00:00:00Z',
      networkPort: 443,
      networkTransport: 'tcp',
      networkService: 'https',
    },
    scannerOutput: {
      text: `heartbeat extension\n<script>alert(1)</script> ${RLO}txt`,
      updatedAt: '2026-10-01T00:00:00Z',
      truncated: false,
    },
    ...over,
  } as FindingDetail
}

describe('Finding overview: scanner facts and output', () => {
  it('labels VPR as an input that does not drive priority', () => {
    render(<OverviewTab finding={finding()} />)
    expect(screen.getByText('Tenable VPR (input)')).toBeInTheDocument()
    expect(screen.getByText(/not used for priority/)).toBeInTheDocument()
  })

  it('shows both CVSS vectors, the version, family, port and patch date', () => {
    render(<OverviewTab finding={finding()} />)
    expect(screen.getByText('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')).toBeInTheDocument()
    expect(screen.getByText('AV:N/AC:L/Au:N/C:P/I:N/A:N')).toBeInTheDocument()
    expect(screen.getByText(/v3\.x/)).toBeInTheDocument()
    expect(screen.getByText('General')).toBeInTheDocument()
    expect(screen.getByText('443/tcp · https')).toBeInTheDocument()
    expect(screen.getByText('Apr 7, 2014')).toBeInTheDocument()
  })

  it('lists every CVE, linking only well-formed ids, and the related CVEs', () => {
    const { container } = render(<OverviewTab finding={finding()} />)
    const cves = screen.getByTestId('finding-cves')
    expect(cves).toHaveTextContent('CVE-2014-0160')
    expect(cves).toHaveTextContent('CVE-2014-0346')
    expect(cves.querySelectorAll('a')).toHaveLength(2)
    expect(container.querySelector('script')).toBeNull()
    // Related: CVE-2014-0346 is already listed, so only the other one.
    const related = screen.getByTestId('finding-related-cves')
    expect(related).toHaveTextContent('CVE-2016-2107')
    expect(related).not.toHaveTextContent('CVE-2014-0346')
  })

  it('shows the scanner output escaped, behind a disclosure', () => {
    const { container } = render(<OverviewTab finding={finding()} />)
    expect(screen.getByText('Scanner output')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Show output'))
    const pre = screen.getByTestId('untrusted-text-block')
    expect(pre.textContent).toContain('<script>alert(1)</script>')
    expect(pre.textContent).not.toContain(RLO)
    expect(container.querySelector('script')).toBeNull()
  })

  it('has no scanner output section when there is none', () => {
    render(<OverviewTab finding={finding({ scannerOutput: undefined })} />)
    expect(screen.queryByText('Scanner output')).toBeNull()
  })
})
