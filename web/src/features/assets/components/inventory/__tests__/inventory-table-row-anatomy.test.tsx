import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'

vi.mock('../../asset-detail-sheet', () => ({ AssetDetailSheet: () => null }))
vi.mock('@/features/scope', () => ({
  ScopeCheckBadge: () => null,
  useScopeCheck: () => ({ resultFor: () => undefined, data: undefined }),
}))
vi.mock('@/features/asset-types/api/use-asset-type-registry', () => ({
  useAssetTypeRegistry: () => ({ data: undefined, classAndLens: () => '' }),
}))
vi.mock('../../../hooks/use-asset-tags', () => ({ useAssetTags: () => ({ data: [] }) }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => true }),
}))

import { InventoryTable } from '../inventory-table'
import type { Asset } from '../../../types/asset.types'

const hoursAgo = (h: number) => new Date(Date.now() - h * 3600e3).toISOString()

const base = {
  status: 'active',
  criticality: 'medium',
  exposure: 'public',
  scope: 'external',
  findingCount: 0,
  riskScore: 76,
  riskScored: true,
  lastSeen: hoursAgo(3),
} as const

const http = {
  ...base,
  id: '11111111-2222-3333-4444-555555555551',
  name: 'https://priority-portal.example.vn:443',
  type: 'service',
  subType: 'http',
  metadata: { status_code: 200, port: 443, protocol: 'https', ip_addresses: ['4.145.78.2'] },
  technologies: ['nginx', 'React', 'Next.js', 'HSTS', 'jQuery'].map((name) => ({
    name,
    category: 'web',
  })),
} as unknown as Asset

const stale = {
  ...base,
  id: '11111111-2222-3333-4444-555555555552',
  name: 'old.example.vn',
  type: 'subdomain',
  status: 'stale',
  lastSeen: hoursAgo(24 * 20),
} as unknown as Asset

function renderTable(assets: Asset[]) {
  return render(
    <InventoryTable
      assets={assets}
      total={assets.length}
      page={1}
      pageSize={20}
      onPageChange={() => {}}
      onSortChange={() => {}}
      onSelectionChange={() => {}}
      resetSelectionKey={0}
      hasFilters={false}
    />
  )
}

function row(name: string) {
  return screen.getAllByRole('row').find((r) => r.textContent?.includes(name)) as HTMLElement
}

describe('InventoryTable row anatomy (research/266)', () => {
  it('Last seen shows a time, not the lifecycle state of an active asset', () => {
    renderTable([http])
    const r = row('priority-portal')
    expect(within(r).getByText(/3 hours ago/)).toBeInTheDocument()
    expect(within(r).queryByText('Active')).toBeNull()
  })

  it('a stale asset shows its time and its state', () => {
    renderTable([stale])
    const r = row('old.example.vn')
    expect(within(r).getByText(/20 days ago/)).toBeInTheDocument()
    expect(r.querySelector('[data-state="stale"]')).not.toBeNull()
  })

  it('the type is the name cell second line; the Type column is off by default', () => {
    renderTable([http])
    const cell = within(row('priority-portal')).getByTestId('asset-name-cell')
    expect(cell.querySelector('[data-slot="asset-type-line"]')?.textContent).toBeTruthy()
    expect(screen.queryByRole('columnheader', { name: /^Type/ })).toBeNull()
  })

  it('service facts are one line: status, port, top technology, then +N', () => {
    renderTable([http])
    const line = within(row('priority-portal')).getByTestId('surface-facts-line')
    expect(line.className).toContain('flex-nowrap')
    const chips = [...line.querySelectorAll('[data-slot="fact-chip"]')].map((c) => c.textContent)
    expect(chips.slice(0, 3)).toEqual(['200OK', '443/https', 'nginx'])
    // 4 more technologies, the IP and TLS sit behind "+6".
    expect(within(line).getByRole('button', { name: '6 more facts' })).toHaveTextContent('+6')
  })

  it('an asset with no owner reads a muted "No owner"', () => {
    renderTable([http])
    expect(within(row('priority-portal')).getByText('No owner')).toBeInTheDocument()
  })

  it('criticality and exposure carry their tone, not one grey', () => {
    renderTable([http])
    const r = row('priority-portal')
    expect(r.querySelector('[data-slot="tag"][data-level="2"]')).not.toBeNull()
    expect(r.querySelector('[data-slot="tone-chip"][data-value="public"]')).toHaveAttribute(
      'data-tone',
      'caution'
    )
  })
})
