/**
 * Opening the findings list for one asset (owner report 2026-10-17: the page
 * "jumped"). Arriving from /assets?sort=-risk_score, the page rendered once
 * with the previous page's query string still in the address bar and sent
 * GET /findings?…&sort=-risk_score without the asset (400), then fetched again;
 * and the overview strip kept counting every finding while the list showed
 * the asset's three.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, render, screen } from '@testing-library/react'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const ASSET_ID = '019feab9-1111-7222-8333-444455556666'

type Call = { filters: Record<string, unknown>; enabled: boolean }
const listCalls: Call[] = []
const statsCalls: Call[] = []

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  // The router already renders the new page: its pathname is the target's.
  usePathname: () => '/findings',
  useSearchParams: () => new URLSearchParams(window.location.search),
}))

vi.mock('swr', () => ({
  default: vi.fn(() => ({ data: undefined, error: undefined, isLoading: false, mutate: vi.fn() })),
  mutate: vi.fn(),
  useSWRConfig: () => ({ mutate: vi.fn() }),
}))

const ALL = {
  total: 114,
  by_severity: {},
  by_status: {},
  open_count: 104,
  by_state: { open: 104, fixed: 6, dispositioned: 4, all: 114 },
  open_by_severity: { critical: 21 },
  kev_open: 0,
  sla_breached: 0,
  awaiting_verification: 0,
}
const ASSET = {
  ...ALL,
  total: 3,
  open_count: 3,
  by_state: { open: 3, fixed: 0, dispositioned: 0, all: 3 },
  open_by_severity: { critical: 1 },
}

vi.mock('@/features/findings/api/use-findings-api', async (orig) => {
  const actual = await orig<typeof import('@/features/findings/api/use-findings-api')>()
  return {
    buildFindingStatsUrl: actual.buildFindingStatsUrl,
    buildFindingsEndpoint: actual.buildFindingsEndpoint,
    useFindingApi: () => ({ data: undefined }),
    useFindingsApi: (filters: Record<string, unknown>, config?: { enabled?: boolean }) => {
      listCalls.push({ filters, enabled: config?.enabled ?? true })
      return {
        data: { data: [], total: 0, page: 1, per_page: 20 },
        error: undefined,
        isLoading: false,
        mutate: vi.fn(),
      }
    },
    useFindingStatsApi: (filters: Record<string, unknown>, config?: { enabled?: boolean }) => {
      statsCalls.push({ filters, enabled: config?.enabled ?? true })
      const url = actual.buildFindingStatsUrl(filters as never)
      return { data: url.includes('asset_id=') ? ASSET : ALL, isLoading: false, mutate: vi.fn() }
    },
    buildFindingsExportUrl: () => '#',
    invalidateFindingsCache: vi.fn(),
  }
})

vi.mock('@/features/config/api/finding-source-api', () => ({
  useFindingSourcesApi: () => ({ data: undefined }),
  groupFindingSourcesByCategory: () => [],
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => true,
}))
vi.mock('@/features/saved-views/components/saved-views-menu', () => ({
  SavedViewsMenu: () => null,
}))
vi.mock('@/components/layout', () => ({
  Main: ({ children }: { children: React.ReactNode }) => <main>{children}</main>,
}))
vi.mock('@/features/findings/components/auto-assign-dialog', () => ({
  AutoAssignDialog: () => null,
}))
vi.mock('@/features/findings/components/mark-fixed-dialog', () => ({ MarkFixedDialog: () => null }))
vi.mock('@/features/findings/components/create-ticket-dialog', () => ({
  CreateTicketDialog: () => null,
}))
vi.mock('@/features/remediation-hub/components/add-findings-to-task-dialog', () => ({
  AddFindingsToTaskDialog: () => null,
}))
vi.mock('@/features/findings', async (orig) => ({
  ...(await orig<typeof import('@/features/findings')>()),
  FindingDetailDrawer: () => null,
  CreateFindingDialog: () => null,
}))
vi.mock('@/features/assets/hooks/use-assets', () => ({
  useAsset: () => ({ asset: { id: ASSET_ID, name: 'www.example.test' }, isLoading: false }),
}))

import FindingsPage from '../page'
import {
  buildFindingStatsUrl,
  buildFindingsEndpoint,
} from '@/features/findings/api/use-findings-api'

const sentList = () =>
  listCalls.filter((c) => c.enabled).map((c) => buildFindingsEndpoint(c.filters as never))
const sentStats = () =>
  new Set(statsCalls.filter((c) => c.enabled).map((c) => buildFindingStatsUrl(c.filters as never)))
const card = (label: RegExp) => screen.getByRole('button', { name: label })

beforeEach(() => {
  listCalls.length = 0
  statsCalls.length = 0
})

describe('Findings opened for an asset', () => {
  it('sends no request while the address bar still holds the previous page', () => {
    // Client-side navigation: the router renders /findings before it writes
    // /findings?asset_id=… to the address bar.
    window.history.replaceState(null, '', '/assets?sort=-risk_score')
    render(<FindingsPage />)

    expect(listCalls.length).toBeGreaterThan(0)
    expect(sentList()).toEqual([])
    expect(sentStats().size).toBe(0)
    // Nothing from the previous page's params is shown either.
    expect(screen.queryByTestId('context-chip-asset_id')).toBeNull()

    // The router commits the URL; the page re-renders with its own params.
    act(() => {
      window.history.pushState(null, '', `/findings?asset_id=${ASSET_ID}`)
      window.dispatchEvent(new PopStateEvent('popstate'))
    })

    const sent = sentList()
    expect(sent.length).toBeGreaterThan(0)
    for (const url of sent) {
      expect(url).toContain(`asset_id=${ASSET_ID}`)
      expect(url).not.toContain('risk_score')
    }
    // One list URL: no second request for the same view.
    expect(new Set(sent).size).toBe(1)
    expect(screen.getByTestId('context-chip-asset_id')).toBeInTheDocument()
  })

  it('keeps a linked page number on the first settled render', () => {
    window.history.replaceState(null, '', '/assets?sort=-risk_score')
    render(<FindingsPage />)
    act(() => {
      window.history.pushState(null, '', `/findings?asset_id=${ASSET_ID}&page=3`)
      window.dispatchEvent(new PopStateEvent('popstate'))
    })
    const sent = sentList()
    expect(sent.length).toBeGreaterThan(0)
    expect(sent.every((u) => u.includes('page=3'))).toBe(true)
    expect(new URLSearchParams(window.location.search).get('page')).toBe('3')
  })

  it('scopes the overview strip to the asset, in the same single stats request as the tabs', () => {
    window.history.replaceState(null, '', `/findings?asset_id=${ASSET_ID}`)
    render(<FindingsPage />)

    const stats = sentStats()
    expect(stats.size).toBe(1)
    expect([...stats][0]).toContain(`asset_id=${ASSET_ID}`)
    expect(card(/^Total/)).toHaveTextContent('3')
    expect(card(/^Open/)).toHaveTextContent('3')
    expect(screen.getByRole('radio', { name: /^All/ })).toHaveTextContent('3')
    expect(card(/^Total/)).toHaveAttribute('title', expect.stringContaining('scope'))
  })

  it('a facet filter on top of the asset moves the tab counts, not the strip', () => {
    window.history.replaceState(null, '', `/findings?asset_id=${ASSET_ID}&severity=low`)
    render(<FindingsPage />)

    const stats = [...sentStats()]
    expect(stats).toHaveLength(2)
    expect(stats.every((u) => u.includes(`asset_id=${ASSET_ID}`))).toBe(true)
    expect(stats.filter((u) => u.includes('severity=low'))).toHaveLength(1)
  })
})
