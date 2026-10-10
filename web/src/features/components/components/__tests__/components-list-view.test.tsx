import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ComponentListResponse, ComponentPackage } from '../../api/types'

const listCalls: Record<string, unknown>[] = []
let listResponse: ComponentListResponse | undefined
vi.mock('../../api/hooks', () => ({
  useComponentsList: (params: Record<string, unknown>) => {
    listCalls.push(params)
    return { data: listResponse, error: undefined, isLoading: false, mutate: vi.fn() }
  },
  useComponentsSummary: () => ({
    data: {
      packages: 2,
      versions: 3,
      assets: 4,
      vulnerable_packages: 1,
      kev_packages: 1,
      fixable_packages: 1,
      outdated: null,
      license_violations: null,
    },
    isLoading: false,
  }),
  importSbom: vi.fn(),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => children,
  Permission: {
    ComponentsWrite: 'assets:components:write',
    ComponentsRead: 'assets:components:read',
  },
}))
vi.mock('../sbom-import-dialog', () => ({ SbomImportDialog: () => null }))
vi.mock('../sbom-export-dialog', () => ({ SbomExportDialog: () => null }))

import { ComponentsListView } from '../components-list-view'

const pkg = (over: Partial<ComponentPackage>): ComponentPackage => ({
  id: 'p1',
  name: 'lodash',
  ecosystem: 'npm',
  purl_type: 'npm',
  purl: 'pkg:npm/lodash',
  versions_in_use: 2,
  assets: 3,
  direct_links: 2,
  transitive_links: 1,
  vulnerabilities: { critical: 1, high: 2, medium: 0, low: 0 },
  kev: 1,
  fix_available: true,
  licenses: ['MIT'],
  risk_score: 92,
  first_seen_at: '2026-10-01T00:00:00Z',
  last_seen_at: '2026-10-09T00:00:00Z',
  ...over,
})

beforeEach(() => {
  listCalls.length = 0
  window.history.replaceState(null, '', '/components')
  listResponse = {
    data: [pkg({})],
    total: 1,
    page: 1,
    per_page: 25,
    total_pages: 1,
    facets: {
      ecosystem: [
        { value: 'npm', count: 1 },
        { value: 'pypi', count: 3 },
      ],
    },
  }
})

describe('components list', () => {
  it('shows one row per package with its counts and a link to its page', () => {
    render(<ComponentsListView />)
    const link = screen.getByRole('link', { name: 'lodash' })
    expect(link.getAttribute('href')).toBe('/components/p1')
    const row = link.closest('tr') as HTMLElement
    expect(within(row).getByText('pkg:npm/lodash')).toBeTruthy()
    expect(within(row).getByText('MIT')).toBeTruthy()
    expect(within(row).getByLabelText(/1 Critical, 2 High/)).toBeTruthy()
  })

  it('asks the API for the default sort and page and the facets', () => {
    render(<ComponentsListView />)
    expect(listCalls.at(-1)).toMatchObject({ page: 1, per_page: 25, sort: '-risk' })
  })

  it('keeps a facet choice in the URL and sends it to the API', async () => {
    render(<ComponentsListView />)
    const pypi = screen.getAllByRole('checkbox', { name: /pypi/ })[0]
    await userEvent.click(pypi)
    expect(new URLSearchParams(window.location.search).get('ecosystem')).toBe('pypi')
    expect(listCalls.at(-1)).toMatchObject({ ecosystem: 'pypi' })
  })

  it('applies a preset from the KPI strip', async () => {
    render(<ComponentsListView />)
    await userEvent.click(screen.getAllByRole('radio', { name: /known exploited/i })[0])
    expect(new URLSearchParams(window.location.search).get('kev')).toBe('true')
  })

  it('explains how to get data when the inventory is empty', () => {
    listResponse = { data: [], total: 0, page: 1, per_page: 25, total_pages: 0, facets: {} }
    render(<ComponentsListView />)
    expect(screen.getByText('No components yet')).toBeTruthy()
    expect(screen.getByRole('link', { name: 'Set up a sensor' }).getAttribute('href')).toBe(
      '/sensors'
    )
  })

  it('says nothing matches when filters hide everything', () => {
    window.history.replaceState(null, '', '/components?kev=true')
    listResponse = { data: [], total: 0, page: 1, per_page: 25, total_pages: 0, facets: {} }
    render(<ComponentsListView />)
    expect(screen.queryByText('No components yet')).toBeNull()
    expect(screen.getByText('No packages match these filters')).toBeTruthy()
  })
})
