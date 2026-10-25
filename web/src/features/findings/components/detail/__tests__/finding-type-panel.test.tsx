import { describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import type { FindingDetail } from '../../../types'

let evidenceData: unknown[] = []
vi.mock('../../../api/use-finding-evidence-items', () => ({
  useFindingEvidenceItems: () => ({ data: { data: evidenceData } }),
  revealEvidence: vi.fn(),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { EvidenceReveal: 'findings:evidence:reveal' },
  useHasPermission: () => false,
}))
const { FindingTypePanel } = await import('../finding-type-panel')

function finding(over: Partial<FindingDetail> = {}): FindingDetail {
  return {
    id: 'f1',
    title: 'Request data reaches a command',
    description: '',
    severity: 'high',
    status: 'new',
    source: 'sast',
    assets: [],
    evidence: [],
    remediation: { description: '', steps: [], references: [], progress: 0 },
    relatedFindings: [],
    discoveredAt: '2026-10-15T00:00:00Z',
    createdAt: '2026-10-15T00:00:00Z',
    updatedAt: '2026-10-15T00:00:00Z',
    activities: [],
    ...over,
  } as FindingDetail
}

describe('FindingTypePanel', () => {
  it('shows the SAST data flow from source to sink and links the code at the commit', () => {
    render(
      <FindingTypePanel
        finding={finding({
          repositoryUrl: 'https://gitlab.com/acme/app',
          filePath: 'app/app.py',
          startLine: 13,
          dataFlow: {
            commitSha: '67da69d5701fb12f',
            steps: [
              {
                type: 'source',
                path: 'app/app.py',
                line: 12,
                content: 'request.args.get("cmd")',
                index: 0,
              },
              { type: 'intermediate', path: 'app/app.py', line: 12, content: 'cmd', index: 1 },
              {
                type: 'sink',
                path: 'app/app.py',
                line: 13,
                content: 'subprocess.check_output(cmd, shell=True)',
                index: 2,
              },
            ],
          },
        })}
      />
    )
    const s = screen.getByRole('region', { name: /Data flow/ })
    const steps = within(s).getAllByRole('listitem')
    expect(steps).toHaveLength(3)
    expect(steps[0]).toHaveTextContent('Sourceapp/app.py:12request.args.get("cmd")')
    expect(steps[2]).toHaveTextContent('Sinkapp/app.py:13')
    expect(within(s).getByRole('link', { name: /Open the code/ })).toHaveAttribute(
      'href',
      'https://gitlab.com/acme/app/-/blob/67da69d5701fb12f/app/app.py#L13'
    )
  })

  it('shows a secret masked and never its value', () => {
    render(
      <FindingTypePanel
        finding={finding({
          source: 'secret',
          filePath: 'app/settings.py',
          startLine: 2,
          secretDetails: {
            secretType: 'api_key',
            maskedValue: 'Zq8…',
          } as FindingDetail['secretDetails'],
        })}
      />
    )
    const s = screen.getByRole('region', { name: 'Secret' })
    expect(s).toHaveTextContent('Masked valueZq8…')
    expect(s).toHaveTextContent('Not verified by the scanner')
    expect(s).toHaveTextContent('app/settings.py:2')
  })

  it('renders nothing for a dependency finding', () => {
    const { container } = render(<FindingTypePanel finding={finding({ source: 'sca' })} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the request and response of a web finding, not the tool curl item stored after it', () => {
    const at = '2026-10-20T10:00:00Z'
    evidenceData = [
      {
        id: 'c1',
        finding_id: 'f1',
        origin: 'detection',
        kind: 'curl',
        created_at: at,
        captured_at: at,
        revealable: [],
        item: { kind: 'curl', text: "curl 'https://h.example/'" },
      },
      {
        id: 'e1',
        finding_id: 'f1',
        origin: 'detection',
        kind: 'http_exchange',
        created_at: at,
        captured_at: at,
        revealable: [],
        curl: "curl -sS -i 'https://h.example/'",
        item: {
          kind: 'http_exchange',
          http: {
            request: { method: 'GET', url: 'https://h.example/' },
            response: { status: 403, reason: 'Forbidden', body: 'denied' },
          },
        },
      },
      {
        id: 'e0',
        finding_id: 'f1',
        origin: 'retest',
        retest_id: 'r1',
        kind: 'http_exchange',
        created_at: '2026-10-19T10:00:00Z',
        captured_at: '2026-10-19T10:00:00Z',
        revealable: [],
        curl: "curl 'https://h.example/'",
        item: { kind: 'http_exchange', http: { request: { url: 'https://h.example/' } } },
      },
    ]
    const onOpenEvidence = vi.fn()
    render(
      <FindingTypePanel finding={finding({ source: 'dast' })} onOpenEvidence={onOpenEvidence} />
    )
    expect(screen.getAllByTestId('evidence-item')).toHaveLength(1)
    expect(screen.getByText(/403/)).toBeInTheDocument()
    expect(screen.getByText('denied')).toBeInTheDocument()
    screen.getByTestId('evidence-open-all').click()
    expect(onOpenEvidence).toHaveBeenCalled()
    evidenceData = []
  })
})
