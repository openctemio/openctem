import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { CICDIntegration, cicdTab } from '../components/ci-cd-integration'
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
vi.mock('../components/ci-trust-settings', () => ({
  CITrustSettings: ({ embedded }: { embedded?: boolean }) => (
    <div data-testid="trust-settings" data-embedded={String(!!embedded)} />
  ),
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
    expect(screen.queryByTestId('trust-settings')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: /ci integration guide/i })).toHaveAttribute(
      'href',
      DOCS.ci.guide
    )
  })

  it('offers Connect a pipeline in the header to a CI writer only, on every tab', async () => {
    const { unmount } = render(<CICDIntegration />)
    expect(screen.queryByRole('button', { name: 'Connect a pipeline' })).not.toBeInTheDocument()
    // A reader gets no "ask an administrator" line in the header either.
    expect(screen.queryByText(/ask an administrator/i)).not.toBeInTheDocument()
    unmount()
    perms = [Permission.CIWrite]
    render(<CICDIntegration />)
    expect(screen.getByRole('button', { name: 'Connect a pipeline' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Settings' }))
    expect(screen.getByRole('button', { name: 'Connect a pipeline' })).toBeInTheDocument()
  })

  it('shows trust, gate policy and break-glass under Settings, without a second header', async () => {
    render(<CICDIntegration />)
    await userEvent.click(screen.getByRole('tab', { name: 'Settings' }))
    expect(screen.getByTestId('trust-settings')).toHaveAttribute('data-embedded', 'true')
    expect(screen.queryByTestId('pipelines-panel')).not.toBeInTheDocument()
  })

  it('reads the tab from the URL', () => {
    expect(cicdTab('setup')).toBe('setup')
    expect(cicdTab('')).toBe('pipelines')
    expect(cicdTab('anything')).toBe('pipelines')
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
