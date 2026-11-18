import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import {
  CICDIntegration,
  LEGACY_SETUP_SECTIONS,
  canonicalCICDSearch,
  cicdTab,
} from '../components/ci-cd-integration'
import { CIPipelinesHint, pipelineHintCounts } from '../components/ci-pipelines-hint'
import { DOCS } from '@/lib/docs-links'
import { Permission } from '@/lib/permissions'

let pipelineCounts: Record<string, number> | undefined
let lastHintCall: { filters: unknown; enabled?: boolean } | undefined
vi.mock('../api/use-ci', () => ({
  useCIPipelines: (filters: unknown, opts?: { enabled?: boolean }) => {
    lastHintCall = { filters, enabled: opts?.enabled }
    return { data: pipelineCounts === undefined ? undefined : { data: [], counts: pipelineCounts } }
  },
}))

let perms: string[] = []
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: (p: string) => perms.includes(p), isLoading: false }),
}))

vi.mock('../components/ci-pipelines-panel', () => ({
  CIPipelinesPanel: () => <div data-testid="pipelines-panel" />,
}))
vi.mock('../components/ci-connections', () => ({
  CIConnections: () => <div data-testid="connections" />,
}))
vi.mock('../components/ci-gate-settings', () => ({
  CIGateSettings: () => <div data-testid="gate" />,
}))
vi.mock('../components/ci-pr-feedback', () => ({
  CIPRFeedback: () => <div data-testid="feedback" />,
}))
vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))

describe('CI/CD integration page', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/ci-cd')
    perms = []
  })

  it('opens on the pipelines, with the CI guide', () => {
    render(<CICDIntegration />)
    expect(screen.getByRole('heading', { name: 'CI/CD integration' })).toBeInTheDocument()
    expect(screen.getByTestId('pipelines-panel')).toBeInTheDocument()
    expect(screen.queryByTestId('connections')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /ci integration guide/i })).toHaveAttribute(
      'href',
      DOCS.ci.guide
    )
  })

  it('offers Connect a CI provider in the header to a CI writer only, on every tab', async () => {
    const { unmount } = render(<CICDIntegration />)
    expect(screen.queryByRole('button', { name: 'Connect a CI provider' })).not.toBeInTheDocument()
    // A reader gets no "ask an administrator" line in the header either.
    expect(screen.queryByText(/ask an administrator/i)).not.toBeInTheDocument()
    unmount()
    perms = [Permission.CIWrite]
    render(<CICDIntegration />)
    expect(screen.getByRole('button', { name: 'Connect a CI provider' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Connections' }))
    expect(screen.getByRole('button', { name: 'Connect a CI provider' })).toBeInTheDocument()
    // One way in: the header's button, no second filled action on the tab.
    expect(screen.getAllByRole('button', { name: 'Connect a CI provider' })).toHaveLength(1)
  })

  it('has one tab per setup job: Connections, Gate and Pull request feedback', async () => {
    render(<CICDIntegration />)
    expect(screen.getAllByRole('tab').map((t) => t.textContent)).toEqual([
      'Pipelines',
      'Runs',
      'Coverage',
      'Connections',
      'Gate',
      'Pull request feedback',
    ])
    await userEvent.click(screen.getByRole('tab', { name: 'Connections' }))
    expect(window.location.search).toBe('?tab=connections')
    expect(screen.getByTestId('connections')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Gate' }))
    expect(screen.getByTestId('gate')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Pull request feedback' }))
    expect(screen.getByTestId('feedback')).toBeInTheDocument()
    expect(screen.queryByTestId('pipelines-panel')).not.toBeInTheDocument()
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1)
  })

  it('reads the tab from the URL', () => {
    expect(cicdTab('connections')).toBe('connections')
    expect(cicdTab('gate')).toBe('gate')
    expect(cicdTab('feedback')).toBe('feedback')
    expect(cicdTab('', 'runs')).toBe('runs')
    expect(cicdTab('')).toBe('pipelines')
    expect(cicdTab('anything')).toBe('pipelines')
  })

  // Server alerts and e-mails, the GitHub App callback, the scope page and
  // bookmarks carry the old single Settings tab and its sections.
  it.each([
    ['?tab=setup', 'tab=connections'],
    ['?tab=setup&section=trust', 'tab=connections'],
    ['?tab=setup&section=refused', 'tab=connections&refused=1'],
    ['?tab=setup&section=gate', 'tab=gate'],
    ['?tab=setup&section=feedback', 'tab=feedback'],
    ['?tab=setup&section=break-glass', 'view=runs&section=break-glass'],
    ['?tab=setup&section=unknown', 'tab=connections'],
    ['?org=t-1&tab=setup', 'org=t-1&tab=connections'],
  ])('rewrites the old link %s to %s', (from, to) => {
    expect(canonicalCICDSearch(from)).toBe(to)
    const params = new URLSearchParams(from)
    const want = new URLSearchParams(to)
    expect(cicdTab(params.get('tab') ?? '', '', params.get('section') ?? '')).toBe(
      want.get('tab') ?? 'runs'
    )
  })

  it('leaves a current address alone, and covers every old section', () => {
    expect(canonicalCICDSearch('?tab=gate')).toBeNull()
    expect(canonicalCICDSearch('?view=runs&run=r1')).toBeNull()
    expect(Object.keys(LEGACY_SETUP_SECTIONS).sort()).toEqual(
      ['', 'break-glass', 'feedback', 'gate', 'refused', 'trust'].sort()
    )
  })

  it('opens an old Settings link on its new tab and rewrites the address', () => {
    window.history.replaceState(null, '', '/ci-cd?tab=setup&section=gate')
    render(<CICDIntegration />)
    expect(screen.getByTestId('gate')).toBeInTheDocument()
    expect(window.location.search).toBe('?tab=gate')
  })
})

describe('CIPipelinesHint (the Sensors page line to CI/CD)', () => {
  beforeEach(() => {
    pipelineCounts = undefined
    lastHintCall = undefined
  })

  it('counts active pipelines (not archived, retired or revoked) and failing gates', () => {
    expect(
      pipelineHintCounts({ fresh: 10, stale: 2, failing: 1, archived: 4, revoked: 1 })
    ).toEqual({
      active: 13,
      failing: 1,
    })
    expect(pipelineHintCounts(undefined)).toEqual({ active: 0, failing: 0 })
  })

  it('is one line linking to CI/CD, with the failing gates linking to that filter', () => {
    pipelineCounts = { fresh: 11, stale: 2, failing: 1, archived: 3 }
    render(<CIPipelinesHint enabled />)
    expect(
      screen.getByRole('link', { name: /14 ci pipelines report through ci\/cd/i })
    ).toHaveAttribute('href', '/ci-cd')
    expect(screen.getByRole('link', { name: /1 failing gate/i })).toHaveAttribute(
      'href',
      '/ci-cd?pipeline_status=failing'
    )
    // A single row is enough for the counts; never the pipeline list.
    expect(lastHintCall?.filters).toEqual({ perPage: 1 })
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  it('says nothing about failing when every gate passes', () => {
    pipelineCounts = { fresh: 1 }
    render(<CIPipelinesHint enabled />)
    expect(
      screen.getByRole('link', { name: /1 ci pipeline reports through ci\/cd/i })
    ).toBeInTheDocument()
    expect(screen.queryByText(/failing/i)).not.toBeInTheDocument()
  })

  it('renders nothing without an active pipeline', () => {
    pipelineCounts = { archived: 2 }
    const { container } = render(<CIPipelinesHint enabled />)
    expect(container).toBeEmptyDOMElement()
  })

  it('does not ask the API for a caller who may not read CI', () => {
    pipelineCounts = { fresh: 5 }
    const { container } = render(<CIPipelinesHint enabled={false} />)
    expect(lastHintCall?.enabled).toBe(false)
    expect(container).toBeEmptyDOMElement()
  })
})
