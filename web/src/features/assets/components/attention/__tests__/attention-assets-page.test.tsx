/**
 * Needs attention, asset reasons: each reason lists the inventory under one
 * fixed filter (with the default attribution, so names awaiting review stay
 * out), says how many assets it holds, links to the same filter in the
 * inventory, and shows nothing without assets:read.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { AssetSearchFilters } from '../../../hooks/use-assets'

const state = vi.hoisted(() => ({
  canRead: true,
  queries: [] as AssetSearchFilters[],
  total: 468,
  isLoading: false,
  hasLoaded: true,
  error: undefined as unknown,
  phone: false,
  canWrite: false,
  setPagination: vi.fn(),
  setSorting: vi.fn(),
  tableProps: {} as Record<string, unknown>,
  headerProps: {} as Record<string, unknown>,
}))

vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
  useLinkStatus: () => ({ pending: false }),
}))
vi.mock('@/lib/permissions', () => ({
  Permission: { AssetsRead: 'assets:read', AssetsWrite: 'assets:write' },
  usePermissions: () => ({ can: (p: string) => p === 'assets:read' && state.canRead }),
}))
vi.mock('../../../hooks/use-assets', () => ({
  useAssets: (q: AssetSearchFilters) => {
    state.queries.push(q)
    return {
      assets: [],
      total: state.total,
      isLoading: state.isLoading,
      hasLoaded: state.hasLoaded,
      error: state.error,
      mutate: vi.fn(),
    }
  },
}))
vi.mock('../../assets-section-tabs', () => ({ AssetsSectionTabs: () => null }))
vi.mock('../attention-queue-header', () => ({
  AttentionQueueHeader: (p: {
    reason: string
    count?: number
    inventoryHref?: string
    moreItems?: unknown[]
  }) => {
    state.headerProps = p
    return (
      <div data-testid="queue-header" data-reason={p.reason} data-count={p.count}>
        <a href={p.inventoryHref}>Open in the inventory</a>
      </div>
    )
  },
}))
vi.mock('../../inventory/inventory-table', () => ({
  InventoryTable: (p: { total: number; errorState?: React.ReactNode }) => {
    state.tableProps = p
    return (
      <div data-testid="table">
        {p.total}
        {p.errorState}
      </div>
    )
  },
}))
vi.mock('../../inventory/inventory-bulk-bar', () => ({
  useInventoryTableBulk: () => ({
    bulk: state.canWrite ? { rowLabel: () => '' } : undefined,
    dialogs: null,
    resetKey: 0,
    clear: () => {},
  }),
}))
vi.mock('@/hooks/use-mobile', () => ({ useIsMobile: () => state.phone }))
vi.mock('@/hooks/use-list-params', () => ({
  useListParams: (o: { defaultSort: string }) => ({
    page: 2,
    perPage: 50,
    sort: o.defaultSort,
    setPagination: state.setPagination,
    setSorting: state.setSorting,
  }),
}))

import { AttentionAssetsPage } from '../attention-assets-page'

beforeEach(() => {
  state.canRead = true
  state.queries = []
  state.total = 468
  state.isLoading = false
  state.hasLoaded = true
  state.error = undefined
  state.phone = false
  state.canWrite = false
  state.setPagination.mockClear()
  state.setSorting.mockClear()
})

describe('AttentionAssetsPage', () => {
  it.each([
    ['no_owner', { hasOwner: false }, 'has_owner=false'],
    ['context', { criticalities: ['none'] }, 'criticalities=none'],
    ['unscanned', { coverage: 'uncovered' }, 'coverage=uncovered'],
  ] as const)('%s lists the inventory under its filter and links to it', (reason, filter, qs) => {
    render(<AttentionAssetsPage reason={reason} />)
    const q = state.queries.at(-1)!
    expect(q).toMatchObject(filter)
    // The default inventory: names awaiting review and not ours stay out.
    expect(q.attribution).not.toContain('needs_review')
    expect(q.attribution).not.toContain('rejected')
    const header = screen.getByTestId('queue-header')
    expect(header).toHaveAttribute('data-reason', reason)
    expect(header).toHaveAttribute('data-count', '468')
    expect(screen.getByRole('link', { name: /open in the inventory/i })).toHaveAttribute(
      'href',
      `/assets?${qs}`
    )
    // One tab row only: the reasons are no longer a second tablist.
    expect(screen.queryByRole('navigation', { name: 'Needs attention reasons' })).toBeNull()
    expect(screen.queryByTestId('attention-summary')).toBeNull()
  })

  it('shows only the access message without assets:read, and asks for nothing it shows', () => {
    state.canRead = false
    render(<AttentionAssetsPage reason="no_owner" />)
    expect(screen.getByText('You do not have access to assets')).toBeInTheDocument()
    expect(screen.queryByTestId('table')).toBeNull()
  })

  it('reads page, size and riskiest-first sort from the address and writes changes there', () => {
    render(<AttentionAssetsPage reason="no_owner" />)
    expect(state.queries.at(-1)).toMatchObject({ page: 2, pageSize: 50, sort: '-risk_score' })
    const table = state.tableProps as {
      onPageChange: (p: number, size: number) => void
      onSortChange: (s: string | undefined) => void
    }
    table.onPageChange(3, 50)
    expect(state.setPagination).toHaveBeenCalledWith({ pageIndex: 2, pageSize: 50 })
    table.onSortChange('name')
    expect(state.setSorting).toHaveBeenCalledWith([{ id: 'name', desc: false }])
    table.onSortChange(undefined)
    expect(state.setSorting).toHaveBeenLastCalledWith([])
  })

  it('the first read draws skeleton rows and no count; a later read keeps the rows', () => {
    state.isLoading = true
    state.hasLoaded = false
    const { unmount } = render(<AttentionAssetsPage reason="no_owner" />)
    expect(state.tableProps).toMatchObject({ isLoading: true, isRefreshing: false })
    expect(screen.getByTestId('queue-header')).not.toHaveAttribute('data-count')
    unmount()
    state.hasLoaded = true
    render(<AttentionAssetsPage reason="no_owner" />)
    expect(state.tableProps).toMatchObject({ isLoading: false, isRefreshing: true })
  })

  it('a failed read says what failed in the table and keeps the header', () => {
    state.error = Object.assign(new Error('boom'), { statusCode: 500 })
    render(<AttentionAssetsPage reason="no_owner" />)
    expect(screen.getByTestId('queue-header')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('a refused read shows the access message instead of the queue', () => {
    state.error = Object.assign(new Error('forbidden'), { statusCode: 403, code: 'FORBIDDEN' })
    render(<AttentionAssetsPage reason="no_owner" />)
    expect(screen.queryByTestId('table')).toBeNull()
  })

  it('on a phone, a user who may act on several assets finds Select in the queue More', () => {
    state.phone = true
    state.canWrite = true
    render(<AttentionAssetsPage reason="no_owner" />)
    const items = state.headerProps.moreItems as { id: string }[]
    expect(items.map((i) => i.id)).toEqual(['select'])
    expect(state.tableProps.selectMode).toBeDefined()
  })

  it('no Select without a bulk action', () => {
    state.phone = true
    render(<AttentionAssetsPage reason="no_owner" />)
    expect(state.headerProps.moreItems).toBeUndefined()
  })
})
