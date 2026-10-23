import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

type R = Record<string, unknown>
const s: {
  versions: R
  usages: R
  vulns: R
  paths: R
  graph: R
  usageCalls: R[]
  vulnCalls: R[]
} = { versions: {}, usages: {}, vulns: {}, paths: {}, graph: {}, usageCalls: [], vulnCalls: [] }
const mutate = vi.fn()

const pkg = {
  id: 'p1',
  name: 'lodash',
  ecosystem: 'npm',
  purl: 'pkg:npm/lodash',
  global: true,
  licenses: [],
  kev: 0,
  fix_available: false,
  risk_score: 10,
  versions_in_use: 2,
  assets: 1,
  direct_links: 1,
  transitive_links: 0,
  vulnerabilities: { critical: 0, high: 1, medium: 0, low: 0 },
}
const usage = {
  id: 'u1',
  asset_id: 'a1',
  asset_name: 'web-app',
  asset_type: 'repository',
  version_id: 'v1',
  version: '4.17.0',
  name: 'lodash',
  relationship: 'direct',
  scope: 'runtime',
  location: 'package.json',
  open_findings: 1,
  licenses: [],
}
const vuln = (over: R) => ({
  vulnerability_id: 'vuln-1',
  cve_id: 'CVE-2020-1',
  title: 'Prototype pollution',
  severity: 'high',
  in_cisa_kev: false,
  fixed_versions: [],
  affected_versions: [],
  affected_assets_count: 1,
  open_finding_count: 1,
  total_finding_count: 1,
  ...over,
})

vi.mock('../../api/hooks', () => ({
  useComponent: () => ({ data: pkg, error: undefined, isLoading: false }),
  useComponentVersions: () => ({
    versions: [],
    error: undefined,
    isLoading: false,
    mutate,
    ...s.versions,
  }),
  useComponentUsages: (_id: string, params: R) => {
    s.usageCalls.push(params)
    return { data: undefined, error: undefined, isLoading: false, mutate, ...s.usages }
  },
  useComponentVulnerabilities: (_id: string, params: R) => {
    s.vulnCalls.push(params)
    return { data: undefined, error: undefined, isLoading: false, mutate, ...s.vulns }
  },
  useDependencyPaths: () => ({ paths: [], error: undefined, isLoading: false, mutate, ...s.paths }),
  useDependencyGraph: () => ({
    graph: undefined,
    error: undefined,
    isLoading: false,
    mutate,
    ...s.graph,
  }),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('../vex-statements-panel', () => ({ VexStatementsPanel: () => null }))
vi.mock('../dependency-graph', () => ({ DependencyGraphView: () => <div>graph</div> }))

import { ComponentDetailView } from '../component-detail-view'

beforeEach(() => {
  s.versions = {}
  s.usages = {}
  s.vulns = {}
  s.paths = {}
  s.graph = {}
  s.usageCalls = []
  s.vulnCalls = []
  mutate.mockClear()
  window.history.replaceState(null, '', '/components/p1')
})

describe('component detail states', () => {
  it('shows an error with retry on the Versions tab, then an empty state', async () => {
    s.versions = { error: new Error('boom') }
    const { unmount } = render(<ComponentDetailView id="p1" />)
    expect(screen.getByText(/failed to load the versions/i)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /retry/i }))
    expect(mutate).toHaveBeenCalled()
    unmount()
    s.versions = {}
    render(<ComponentDetailView id="p1" />)
    expect(screen.getByText('No versions in use')).toBeInTheDocument()
  })

  it('reads the Where used version from the URL and shows an error or empty state', () => {
    window.history.replaceState(null, '', '/components/p1?tab=assets&version=v9')
    s.usages = { error: new Error('boom') }
    const { unmount } = render(<ComponentDetailView id="p1" />)
    expect(s.usageCalls.at(-1)).toMatchObject({ version_id: 'v9', page: 1 })
    expect(screen.getByText(/failed to load where this package is used/i)).toBeInTheDocument()
    unmount()
    s.usages = { data: { data: [], total: 0 } }
    render(<ComponentDetailView id="p1" />)
    expect(screen.getByText('Not used on any asset you can see')).toBeInTheDocument()
  })

  it('shows an error in the dependency graph dialog instead of loading forever', async () => {
    window.history.replaceState(null, '', '/components/p1?tab=assets')
    s.usages = { data: { data: [usage], total: 1 } }
    s.graph = { error: new Error('boom') }
    render(<ComponentDetailView id="p1" />)
    await userEvent.click(screen.getByRole('button', { name: /graph/i }))
    expect(await screen.findByText(/failed to load the dependency graph/i)).toBeInTheDocument()
  })

  it('links a vulnerability by id, and uses plain text when there is nothing to link', () => {
    window.history.replaceState(null, '', '/components/p1?tab=vulnerabilities')
    s.vulns = {
      data: {
        data: [
          vuln({}),
          vuln({ vulnerability_id: '', cve_id: '', title: 'Title only' }),
          vuln({ vulnerability_id: 'vuln-3', cve_id: '', title: 'GHSA-xxxx' }),
        ],
        total: 3,
      },
    }
    render(<ComponentDetailView id="p1" />)
    expect(screen.getByRole('link', { name: 'CVE-2020-1' })).toHaveAttribute(
      'href',
      '/findings?vulnerability_id=vuln-1'
    )
    expect(screen.getByRole('link', { name: 'GHSA-xxxx' })).toHaveAttribute(
      'href',
      '/findings?vulnerability_id=vuln-3'
    )
    expect(screen.getByText('Title only').closest('a')).toBeNull()
  })

  it('returns to page 1 when Include closed findings changes', async () => {
    window.history.replaceState(null, '', '/components/p1?tab=vulnerabilities')
    s.vulns = { data: { data: [vuln({})], total: 80 } }
    render(<ComponentDetailView id="p1" />)
    await userEvent.click(screen.getByRole('button', { name: /next/i }))
    expect(s.vulnCalls.at(-1)).toMatchObject({ page: 2 })
    await userEvent.click(screen.getByRole('checkbox', { name: /include closed findings/i }))
    expect(s.vulnCalls.at(-1)).toMatchObject({ page: 1, include_resolved: true })
  })

  it('hides the Latest version tile when there is no package health data', () => {
    render(<ComponentDetailView id="p1" />)
    expect(screen.queryByText('Latest version')).not.toBeInTheDocument()
  })
})
