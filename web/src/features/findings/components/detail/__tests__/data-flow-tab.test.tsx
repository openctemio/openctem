import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { FindingDetail } from '../../../types'
import type { ApiDataFlow } from '../../../api/finding-api.types'
import { mapDataFlow } from '../../../lib/finding-detail'

vi.mock('@/lib/clipboard', () => ({ copyToClipboard: vi.fn(async () => true) }))

const { DataFlowTab } = await import('../data-flow-tab')

function finding(over: Partial<FindingDetail> = {}): FindingDetail {
  return {
    id: 'f1',
    title: 'SQL injection',
    description: '',
    severity: 'high',
    status: 'new',
    source: 'sast',
    assets: [],
    evidence: [],
    remediation: { description: '', steps: [], references: [], progress: 0 },
    relatedFindings: [],
    discoveredAt: '2026-10-01T00:00:00Z',
    createdAt: '2026-10-01T00:00:00Z',
    updatedAt: '2026-10-01T00:00:00Z',
    activities: [],
    ...over,
  } as FindingDetail
}

// The API's ordered trace: source, sanitizer, sink (the sanitizer between).
const apiFlow: ApiDataFlow = {
  sources: [{ path: 'src/routes.js', line: 9, snippet: 'const id = req.query.id', index: 0 }],
  sanitizers: [{ path: 'src/db.js', line: 21, snippet: 'escape(id)', index: 1 }],
  sinks: [{ path: 'src/db.js', line: 22, snippet: 'db.query(q)', index: 2 }],
  traces: [
    {
      index: 0,
      commit_sha: '0123456789abcdef0123456789abcdef01234567',
      steps: [
        {
          index: 2,
          location_type: 'sink',
          location: { path: 'src/db.js', line: 22, snippet: 'db.query(q)' },
        },
        {
          index: 0,
          location_type: 'source',
          label: 'req.query.id',
          location: {
            path: 'src/routes.js',
            line: 9,
            snippet: 'const id = req.query.id',
            function_name: 'getOrder',
          },
        },
        {
          index: 1,
          location_type: 'sanitizer',
          location: { path: 'src/db.js', line: 21, snippet: 'escape(id)' },
        },
      ],
    },
  ],
}

describe('mapDataFlow', () => {
  it('keeps the trace in step order, with the sanitizer and the snippet', () => {
    const df = mapDataFlow(apiFlow)
    expect(df?.steps.map((s) => s.type)).toEqual(['source', 'sanitizer', 'sink'])
    expect(df?.steps[0]).toMatchObject({
      content: 'const id = req.query.id',
      label: 'req.query.id',
      functionName: 'getOrder',
    })
  })

  it('falls back to the grouped locations ordered by index', () => {
    const { traces: _traces, ...grouped } = apiFlow
    expect(mapDataFlow(grouped)?.steps.map((s) => s.type)).toEqual(['source', 'sanitizer', 'sink'])
  })

  it('is undefined without a step', () => {
    expect(mapDataFlow(undefined)).toBeUndefined()
    expect(mapDataFlow({ traces: [{ index: 0, steps: [] }] })).toBeUndefined()
  })
})

describe('DataFlowTab', () => {
  it('says the scanner reported no data flow', () => {
    render(<DataFlowTab finding={finding()} />)
    expect(screen.getByText('This scanner did not report a data flow')).toBeInTheDocument()
  })

  it('renders source, sanitizer and sink in order with file:line and code', () => {
    render(<DataFlowTab finding={finding({ dataFlow: mapDataFlow(apiFlow) })} />)
    const badges = screen.getAllByText(/^Step \d: /).map((b) => b.textContent)
    expect(badges).toEqual(['Step 1: Source', 'Step 2: Sanitizer', 'Step 3: Sink'])
    expect(screen.getByText('src/routes.js')).toBeInTheDocument()
    expect(screen.getAllByText(':22').length).toBeGreaterThan(0)
    expect(screen.getByText('getOrder')).toBeInTheDocument()
    // No repository URL: no link.
    expect(screen.queryByText('View this line at the scanned commit')).not.toBeInTheDocument()
  })

  it('links each step to its file at the scanned commit', () => {
    render(
      <DataFlowTab
        finding={finding({
          dataFlow: mapDataFlow(apiFlow),
          repositoryUrl: 'https://github.com/acme/shop',
          // The finding's latest commit is not the trace's: the trace's wins.
          commitSha: 'ffffffffffffffffffffffffffffffffffffffff',
        })}
      />
    )
    const links = screen.getAllByRole('link', { name: /View this line at the scanned commit/ })
    expect(links).toHaveLength(3)
    expect(links[0]).toHaveAttribute(
      'href',
      'https://github.com/acme/shop/blob/0123456789abcdef0123456789abcdef01234567/src/routes.js#L9'
    )
    expect(links[0]).toHaveAttribute('rel', expect.stringContaining('noopener'))
  })

  it('does not link without the commit the trace was reported for', () => {
    const { traces, ...rest } = apiFlow
    const withoutCommit = { ...rest, traces: traces?.map(({ commit_sha: _c, ...tr }) => tr) }
    render(
      <DataFlowTab
        finding={finding({
          dataFlow: mapDataFlow(withoutCommit),
          repositoryUrl: 'https://github.com/acme/shop',
          commitSha: 'ffffffffffffffffffffffffffffffffffffffff',
        })}
      />
    )
    expect(screen.queryAllByRole('link')).toHaveLength(0)
  })

  it('never links a repository URL with an unsafe scheme', () => {
    render(
      <DataFlowTab
        finding={finding({
          dataFlow: mapDataFlow(apiFlow),
          repositoryUrl: 'javascript:alert(1)',
        })}
      />
    )
    expect(screen.queryAllByRole('link')).toHaveLength(0)
    expect(document.body.innerHTML).not.toContain('javascript:')
  })
})
