/**
 * Asset change timeline (RFC-069 §11): entries grouped by day, newest first,
 * with the diff, reason, source and flap count; filters and "show older"
 * follow the API's cursor; the organization feed links each asset and sends
 * the tag filter; nothing is fetched without assets:read.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'
import { AssetTimeline, RecentAssetChanges } from '../asset-timeline'
import { changesUrl, groupByDay, type AssetChange } from '../../lib/asset-timeline'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
Element.prototype.scrollIntoView = vi.fn()
Element.prototype.hasPointerCapture = vi.fn(() => false)
Element.prototype.releasePointerCapture = vi.fn()

const api = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), del: vi.fn(), post: vi.fn() }))
vi.mock('@/lib/api/client', () => api)

let perms: string[] = []
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: (p: string) => perms.includes(p) }) }
})

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const ev = (over: Partial<AssetChange>): AssetChange => ({
  id: Math.random().toString(36).slice(2),
  asset_id: 'a1',
  at: '2026-10-09T10:00:00Z',
  attribute: 'criticality',
  old_value: 'high',
  new_value: 'critical',
  source: { kind: 'integration', name: 'cmdb', run: 'sync-9' },
  reason: 'newer_observation',
  flap_count: 1,
  ...over,
})

describe('asset timeline helpers', () => {
  it('builds asset and feed URLs with filters and cursor', () => {
    expect(changesUrl('a1', { attribute: 'exposure', tag: 'x' }, 'c1')).toBe(
      '/api/v1/assets/a1/changes?limit=50&attribute=exposure&cursor=c1'
    )
    expect(changesUrl(null, { sourceKind: 'scan', tag: ' bug-bounty ' })).toBe(
      '/api/v1/assets/changes?limit=50&source_kind=scan&tag=bug-bounty'
    )
  })

  it('groups by local day keeping the order', () => {
    const days = groupByDay([
      ev({ at: '2026-10-09T12:00:00' }),
      ev({ at: '2026-10-09T08:00:00' }),
      ev({ at: '2026-10-08T23:00:00' }),
    ])
    expect(days.map((d) => [d.day, d.events.length])).toEqual([
      ['2026-10-09', 2],
      ['2026-10-08', 1],
    ])
  })
})

describe('AssetTimeline', () => {
  beforeEach(() => {
    api.get.mockReset()
    perms = ['assets:read']
  })

  it('shows changes by day with diff, reason, source and flap count', async () => {
    api.get.mockResolvedValue({
      items: [
        ev({ at: '2026-10-09T12:00:00', flap_count: 3 }),
        ev({
          at: '2026-10-08T09:00:00',
          attribute: 'exposure',
          old_value: 'public',
          new_value: 'public',
          source: { kind: 'scan', name: 'nmap', run: '' },
          reason: 'policy_change',
        }),
      ],
      next_cursor: '',
    })
    const onWhy = vi.fn()
    const user = userEvent.setup()
    wrap(<AssetTimeline assetId="a1" onWhy={onWhy} />)
    const entries = await screen.findAllByTestId('timeline-entry')
    expect(entries).toHaveLength(2)
    expect(within(entries[0]).getByText('Newer report')).toBeInTheDocument()
    expect(within(entries[0]).getByText('Changed 3 times within an hour')).toBeInTheDocument()
    expect(
      within(entries[0]).getByText(/Decided by cmdb \(Connector\) · run sync-9/)
    ).toBeInTheDocument()
    expect(within(entries[1]).getByText(/same value, new deciding source/)).toBeInTheDocument()
    expect(within(entries[1]).getByText('Source order changed')).toBeInTheDocument()
    expect(screen.getAllByRole('region')).toHaveLength(2) // two days
    await user.click(within(entries[0]).getByRole('button', { name: 'Why this value' }))
    expect(onWhy).toHaveBeenCalledWith('criticality')
    expect(api.get).toHaveBeenCalledWith('/api/v1/assets/a1/changes?limit=50')
  })

  it('loads older pages with the cursor', async () => {
    api.get.mockImplementation((url: string) =>
      Promise.resolve(
        url.includes('cursor=')
          ? { items: [ev({ at: '2026-10-01T10:00:00', new_value: 'low' })], next_cursor: '' }
          : { items: [ev({})], next_cursor: 'next-1' }
      )
    )
    const user = userEvent.setup()
    wrap(<AssetTimeline assetId="a1" />)
    await user.click(await screen.findByRole('button', { name: 'Show older changes' }))
    await waitFor(() => expect(screen.getAllByTestId('timeline-entry')).toHaveLength(2))
    expect(api.get).toHaveBeenCalledWith('/api/v1/assets/a1/changes?limit=50&cursor=next-1')
    expect(screen.queryByRole('button', { name: 'Show older changes' })).not.toBeInTheDocument()
  })

  it('filters by attribute', async () => {
    api.get.mockResolvedValue({ items: [], next_cursor: '' })
    const user = userEvent.setup()
    wrap(<AssetTimeline assetId="a1" />)
    expect(await screen.findByText('No changes yet')).toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: 'Attribute' }))
    await user.click(await screen.findByRole('option', { name: 'Exposure' }))
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith('/api/v1/assets/a1/changes?limit=50&attribute=exposure')
    )
  })

  it('fetches nothing without assets:read', () => {
    perms = []
    wrap(<AssetTimeline assetId="a1" />)
    expect(api.get).not.toHaveBeenCalled()
  })
})

describe('RecentAssetChanges', () => {
  beforeEach(() => {
    api.get.mockReset()
    perms = ['assets:read']
  })

  it('links each asset and sends the tag filter', async () => {
    api.get.mockResolvedValue({
      items: [ev({ asset_id: 'a9', asset_name: 'shop.example.com' })],
      next_cursor: '',
    })
    const user = userEvent.setup()
    wrap(<RecentAssetChanges />)
    const link = await screen.findByRole('link', { name: 'shop.example.com' })
    expect(link).toHaveAttribute('href', '/assets/a9')
    await user.type(screen.getByRole('textbox', { name: 'Asset tag' }), 'bb')
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith('/api/v1/assets/changes?limit=50&tag=bb')
    )
  })
})
