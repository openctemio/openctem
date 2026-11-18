import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ComponentListResponse, ComponentPackage } from '../../api/types'

const listCalls: Record<string, unknown>[] = []
let listResponse: ComponentListResponse | undefined
let listError: unknown
let canRead = true
const granted = new Set<string>()
const summaryCalls: Record<string, unknown>[] = []
vi.mock('../../api/hooks', () => ({
  useComponentsList: (params: Record<string, unknown>) => {
    listCalls.push(params)
    return {
      data: listResponse,
      error: listError,
      isLoading: false,
      isValidating: false,
      mutate: vi.fn(),
      canRead,
    }
  },
  useComponentsSummary: (params: Record<string, unknown>) => {
    summaryCalls.push(params)
    return {
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
    }
  },
  importSbom: vi.fn(),
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => children,
  usePermissions: () => ({ can: (p: string) => granted.has(p) }),
  Permission: {
    ComponentsWrite: 'assets:components:write',
    ComponentsRead: 'assets:components:read',
    FindingsApprove: 'findings:approve',
  },
}))
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: vi.fn(), prefetch: vi.fn() }),
  usePathname: () => '/components',
  useSearchParams: () => new URLSearchParams(window.location.search),
}))
const push = vi.fn()
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
  listError = undefined
  canRead = true
  push.mockReset()
  granted.clear()
  granted.add('assets:components:write')
  granted.add('findings:approve')
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
    // One line per row: the package URL follows the name (whole in the tooltip).
    expect(within(row).getByText('pkg:npm/lodash')).toBeTruthy()
    expect(within(row).getByTitle('pkg:npm/lodash')).toBeTruthy()
    expect(within(row).getByText('MIT')).toBeTruthy()
    expect(within(row).getByLabelText(/1 Critical, 2 High/)).toBeTruthy()
  })

  it('asks the API for the default sort and page and the facets', () => {
    render(<ComponentsListView />)
    expect(listCalls.at(-1)).toMatchObject({ page: 1, per_page: 25, sort: '-risk' })
  })

  it('keeps a facet choice in the URL and sends it to the API', async () => {
    render(<ComponentsListView />)
    // The facets open from Add filter (no docked panel).
    expect(screen.queryByRole('complementary')).toBeNull()
    await userEvent.click(screen.getAllByRole('button', { name: /add filter/i })[0])
    const pypi = screen.getAllByRole('checkbox', { name: /pypi/ })[0]
    await userEvent.click(pypi)
    expect(new URLSearchParams(window.location.search).get('ecosystem')).toBe('pypi')
    expect(listCalls.at(-1)).toMatchObject({ ecosystem: 'pypi' })
    // The choice shows as a removable chip.
    expect(
      await screen.findByRole('button', { name: 'Remove filter Ecosystem: pypi' })
    ).toBeTruthy()
  })

  it('applies a preset from the KPI strip, with no second row of presets', async () => {
    render(<ComponentsListView />)
    // The tiles are the presets; no segmented control repeats them.
    expect(screen.queryByRole('radiogroup')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /known exploited/i }))
    expect(new URLSearchParams(window.location.search).get('kev')).toBe('true')
    // Packages clears the presets again.
    await userEvent.click(screen.getByRole('button', { name: /packages/i }))
    expect(new URLSearchParams(window.location.search).get('kev')).toBeNull()
  }, 30_000)

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

  it('names the view, counts once, and offers Reset once the list is changed', async () => {
    window.history.replaceState(null, '', '/components?kev=true')
    render(<ComponentsListView />)
    expect(screen.getByRole('heading', { level: 2, name: 'All packages' })).toBeTruthy()
    expect(document.querySelectorAll('[data-slot="list-count"]')).toHaveLength(1)
    expect(document.querySelector('[data-slot="list-modified"]')).not.toBeNull()
    await userEvent.click(screen.getAllByRole('button', { name: 'Reset' })[0])
    expect(new URLSearchParams(window.location.search).get('kev')).toBeNull()
  })

  it('puts Import SBOM in the page title and Import VEX in More, by permission', async () => {
    granted.clear()
    render(<ComponentsListView />)
    expect(screen.queryByRole('button', { name: 'Import SBOM' })).toBeNull()
    expect(screen.getAllByRole('button', { name: 'Export SBOM' }).length).toBeGreaterThan(0)
    // Without findings:approve the wide row has no More at all.
    expect(screen.getAllByRole('button', { name: 'More actions' })).toHaveLength(1)
  })

  it('opens the package page from a row', async () => {
    render(<ComponentsListView />)
    const row = screen.getByRole('link', { name: 'lodash' }).closest('tr') as HTMLElement
    await userEvent.click(within(row).getAllByRole('cell')[1])
    expect(push).toHaveBeenCalledWith('/components/p1')
  })

  it('says so without the read permission and sends no request', () => {
    canRead = false
    listResponse = undefined
    render(<ComponentsListView />)
    expect(screen.getByText(/the components list/i)).toBeTruthy()
    expect(screen.queryByRole('table')).toBeNull()
  })

  it('shows the error in place of the rows', () => {
    listResponse = undefined
    listError = new Error('boom')
    render(<ComponentsListView />)
    expect(screen.queryByRole('link', { name: 'lodash' })).toBeNull()
    expect(screen.getAllByRole('button', { name: /retry|try again/i }).length).toBeGreaterThan(0)
  })

  it('computes the tiles unfiltered and has no inert Outdated tile', async () => {
    window.history.replaceState(null, '', '/components?q=lodash&ecosystem=npm')
    render(<ComponentsListView />)
    expect(summaryCalls.at(-1)).toEqual({})
    expect(screen.queryByText('Outdated')).not.toBeInTheDocument()
  })
})
