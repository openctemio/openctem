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
vi.mock('../../assets-section-tabs', () => ({
  AssetsSectionTabs: () => null,
  AssetAttentionTabs: () => <nav aria-label="Needs attention reasons" />,
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
    ['no_owner', { hasOwner: false }, 'has_owner=false', '468 assets have no owner'],
    [
      'context',
      { criticalities: ['none'] },
      'criticalities=none',
      '468 assets have no criticality',
    ],
    [
      'unscanned',
      { coverage: 'uncovered' },
      'coverage=uncovered',
      '468 assets had no successful scan',
    ],
  ] as const)(
    '%s lists the inventory under its filter and links to it',
    (reason, filter, qs, text) => {
      render(<AttentionAssetsPage reason={reason} />)
      const q = state.queries.at(-1)!
      expect(q).toMatchObject(filter)
      // The default inventory: names awaiting review and not ours stay out.
      expect(q.attribution).not.toContain('needs_review')
      expect(q.attribution).not.toContain('rejected')
      expect(screen.getByTestId('attention-summary')).toHaveTextContent(text)
      expect(screen.getByRole('link', { name: /open in the inventory/i })).toHaveAttribute(
        'href',
        `/assets?${qs}`
      )
      expect(
        screen.getByRole('navigation', { name: 'Needs attention reasons' })
      ).toBeInTheDocument()
    }
  )

  it('one asset reads in the singular', () => {
    state.total = 1
    render(<AttentionAssetsPage reason="no_owner" />)
    expect(screen.getByTestId('attention-summary')).toHaveTextContent('1 asset has no owner')
  })

  it('shows only the access message without assets:read, and asks for nothing it shows', () => {
    state.canRead = false
    render(<AttentionAssetsPage reason="no_owner" />)
    expect(screen.getByText("You don't have access to assets")).toBeInTheDocument()
    expect(screen.queryByTestId('table')).toBeNull()
  })
})
