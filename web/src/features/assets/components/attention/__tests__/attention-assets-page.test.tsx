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
    return { assets: [], total: state.total, isLoading: false, mutate: vi.fn() }
  },
}))
vi.mock('../../assets-section-tabs', () => ({ AssetsSectionTabs: () => null }))
vi.mock('../attention-queue-header', () => ({
  AttentionQueueHeader: (p: { reason: string; count?: number; inventoryHref?: string }) => (
    <div data-testid="queue-header" data-reason={p.reason} data-count={p.count}>
      <a href={p.inventoryHref}>Open in the inventory</a>
    </div>
  ),
}))
vi.mock('../../inventory/inventory-table', () => ({
  InventoryTable: ({ total }: { total: number }) => <div data-testid="table">{total}</div>,
}))
vi.mock('../../inventory/inventory-bulk-bar', () => ({ InventoryBulkBar: () => null }))

import { AttentionAssetsPage } from '../attention-assets-page'

beforeEach(() => {
  state.canRead = true
  state.queries = []
  state.total = 468
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
    expect(screen.getByText("You don't have access to assets")).toBeInTheDocument()
    expect(screen.queryByTestId('table')).toBeNull()
  })
})
