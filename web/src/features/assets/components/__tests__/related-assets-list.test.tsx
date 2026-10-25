/**
 * The grouped related-assets list: plain verbs per direction, counts, paging
 * of large groups, edge source and staleness, one-click navigation, and the
 * data-scope rule that out-of-scope neighbours appear only as a number.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'
import { RelatedAssetsList } from '../relationships/related-assets-list'
import type { RelatedAssetsResponse, RelatedAssetItem } from '../../hooks/use-related-assets'
import { RELATION_VERBS } from '../../lib/relationship-verbs'
import { ALL_RELATIONSHIP_TYPES } from '../../types'
import enAssets from '@/lib/i18n/dictionaries/en/assets.json'
import viAssets from '@/lib/i18n/dictionaries/vi/assets.json'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), del: vi.fn(), put: vi.fn() }))
vi.mock('@/lib/api/client', () => api)

let perms: string[] = ['assets:read']
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: (p: string) => perms.includes(p) }) }
})
let moduleOn = true
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => moduleOn,
}))

const DAY = 86_400_000
const iso = (daysAgo: number) => new Date(Date.now() - daysAgo * DAY).toISOString()

function item(
  id: string,
  name: string,
  over: Partial<RelatedAssetItem> & {
    type: RelatedAssetItem['type']
    direction: RelatedAssetItem['direction']
  },
  asset: Partial<RelatedAssetItem['asset']> = {}
): RelatedAssetItem {
  return {
    relationship_id: `rel-${id}`,
    asset: { id, name, type: 'ip_address', criticality: 'medium', status: 'active', ...asset },
    discovery_method: 'automatic',
    confidence: 'high',
    is_control_plane: false,
    last_verified: iso(0),
    created_at: iso(10),
    ...over,
  }
}

const GROUPED: RelatedAssetsResponse = {
  total: 226,
  hidden_count: 0,
  groups: [
    {
      type: 'runs_on',
      direction: 'outgoing',
      total: 220,
      items: Array.from({ length: 5 }, (_, i) =>
        item(
          `h${i}`,
          `cb-node-00${i}`,
          { type: 'runs_on', direction: 'outgoing' },
          { type: 'host' }
        )
      ),
    },
    {
      type: 'resolves_to',
      direction: 'outgoing',
      total: 2,
      items: [
        item(
          'ip1',
          '203.0.113.21',
          { type: 'resolves_to', direction: 'outgoing' },
          { exposure: 'public' }
        ),
        item('ip2', '203.0.113.22', {
          type: 'resolves_to',
          direction: 'outgoing',
          last_verified: iso(120),
        }),
      ],
    },
    {
      type: 'resolves_to',
      direction: 'incoming',
      total: 1,
      items: [
        item('n1', 'legacy.example.com', {
          type: 'resolves_to',
          direction: 'incoming',
          discovery_method: 'manual',
          last_verified: undefined,
        }),
      ],
    },
    {
      type: 'depends_on',
      direction: 'outgoing',
      total: 3,
      items: [
        item(
          'db',
          'payments-db',
          { type: 'depends_on', direction: 'outgoing', discovery_method: 'manual' },
          {
            type: 'database',
            criticality: 'critical',
          }
        ),
      ],
    },
  ],
}

function wrap(children: ReactNode) {
  return (
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  perms = ['assets:read']
  moduleOn = true
})

describe('RelatedAssetsList (full)', () => {
  it('groups by type and direction with plain verbs, counts and the exposure story first', async () => {
    api.get.mockResolvedValue(GROUPED)
    render(wrap(<RelatedAssetsList assetId="a1" />))

    const groups = await screen.findAllByRole('button', { expanded: true })
    const labels = groups.map((g) => g.textContent)
    // resolves_to (out, in) before runs_on before depends_on.
    expect(labels[0]).toMatch(/^Resolves to2$/)
    expect(labels[1]).toMatch(/^Names that resolve here1$/)
    expect(labels[2]).toMatch(/^Runs on220$/)
    expect(labels[3]).toMatch(/^Depends on3$/)
    expect(screen.getByText('226 related assets in 4 groups')).toBeInTheDocument()
    // No raw keys or title-cased registry labels.
    expect(screen.queryByText(/Resolved By|resolves_to|Contained By/)).not.toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/v1/assets/a1/relationships/groups?limit=5')
  })

  it('shows who recorded each edge and flags one not seen for a month', async () => {
    api.get.mockResolvedValue(GROUPED)
    render(wrap(<RelatedAssetsList assetId="a1" />))
    expect(await screen.findByText(/not seen for 120 days/)).toBeInTheDocument()
    const legacy = screen.getByText('legacy.example.com').closest('li') as HTMLElement
    expect(within(legacy).getByText(/Added by hand · added 10 days ago/)).toBeInTheDocument()
    const ip = screen.getByText('203.0.113.21').closest('li') as HTMLElement
    expect(within(ip).getByText('Internet-facing')).toBeInTheDocument()
    expect(within(ip).getByText(/Scanner · seen today/)).toBeInTheDocument()
  })

  it('opens a related asset in one click, with its id and name', async () => {
    api.get.mockResolvedValue(GROUPED)
    const onNavigate = vi.fn()
    render(wrap(<RelatedAssetsList assetId="a1" onNavigateToAsset={onNavigate} />))
    await userEvent.click(await screen.findByRole('button', { name: 'Open payments-db' }))
    expect(onNavigate).toHaveBeenCalledWith('db', 'payments-db')
  })

  it('pages a large group on the server with a name search instead of loading it all', async () => {
    api.get.mockImplementation(async (url: string) => {
      if (!url.includes('type=runs_on')) return GROUPED
      const q = new URL(url, 'http://x').searchParams
      const total = q.get('q') ? 11 : 220
      const offset = Number(q.get('offset') ?? 0)
      return {
        total,
        hidden_count: 0,
        groups: [
          {
            type: 'runs_on',
            direction: 'outgoing',
            total,
            items: Array.from({ length: Math.min(25, total - offset) }, (_, i) =>
              item(
                `p${offset + i}`,
                `cb-node-${offset + i}`,
                { type: 'runs_on', direction: 'outgoing' },
                { type: 'host' }
              )
            ),
          },
        ],
      }
    })
    render(wrap(<RelatedAssetsList assetId="a1" />))
    await userEvent.click(await screen.findByRole('button', { name: 'Show all 220' }))
    expect(await screen.findByText('1–25 of 220')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith(
      '/api/v1/assets/a1/relationships/groups?type=runs_on&direction=outgoing&limit=25'
    )
    await userEvent.click(screen.getByRole('button', { name: 'Next' }))
    expect(await screen.findByText('26–50 of 220')).toBeInTheDocument()
    await userEvent.type(screen.getByRole('searchbox', { name: 'Search Runs on' }), 'node-1')
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith(
        '/api/v1/assets/a1/relationships/groups?type=runs_on&direction=outgoing&q=node-1&limit=25'
      )
    )
  }, 15_000)

  it('offers edit and remove only when the caller passes them (permission-gated)', async () => {
    api.get.mockResolvedValue(GROUPED)
    const { rerender } = render(wrap(<RelatedAssetsList assetId="a1" />))
    await screen.findByText('payments-db')
    expect(screen.queryByRole('button', { name: /Actions for/ })).not.toBeInTheDocument()

    const onRemove = vi.fn()
    rerender(wrap(<RelatedAssetsList assetId="a1" onRemove={onRemove} />))
    await userEvent.click(await screen.findByRole('button', { name: 'Actions for payments-db' }))
    await userEvent.click(await screen.findByRole('menuitem', { name: 'Remove relationship' }))
    expect(onRemove).toHaveBeenCalledWith(expect.objectContaining({ relationship_id: 'rel-db' }))
    expect(screen.queryByRole('menuitem', { name: 'Edit relationship' })).not.toBeInTheDocument()
  })

  it('shows an error with retry instead of an empty list when the request fails', async () => {
    api.get.mockRejectedValueOnce(new Error('boom')).mockResolvedValue(GROUPED)
    render(wrap(<RelatedAssetsList assetId="a1" />))
    expect(await screen.findByText('Failed to load related assets')).toBeInTheDocument()
    expect(screen.queryByText('No related assets yet')).not.toBeInTheDocument()
  })

  it('explains an empty neighbourhood and places the add action there', async () => {
    api.get.mockResolvedValue({ total: 0, hidden_count: 0, groups: [] })
    render(
      wrap(<RelatedAssetsList assetId="a1" addAction={<button type="button">Add it</button>} />)
    )
    expect(await screen.findByText('No related assets yet')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add it' })).toBeInTheDocument()
  })
})

describe('RelatedAssetsList data scope', () => {
  it('names only in-scope neighbours and counts the rest without a name, type or link', async () => {
    // The API returns one visible neighbour and the number of hidden ones only.
    api.get.mockResolvedValue({
      total: 1,
      hidden_count: 2,
      groups: [
        {
          type: 'depends_on',
          direction: 'outgoing',
          total: 1,
          items: [item('ok', 'in-scope-db', { type: 'depends_on', direction: 'outgoing' })],
        },
      ],
    } satisfies RelatedAssetsResponse)
    const onNavigate = vi.fn()
    const { container } = render(
      wrap(<RelatedAssetsList assetId="a1" onNavigateToAsset={onNavigate} />)
    )
    expect(await screen.findByText('2 related assets you can’t access')).toBeInTheDocument()
    expect(screen.getByText('1 related assets in 1 groups')).toBeInTheDocument()
    // Exactly one navigable neighbour: the hidden ones are not links.
    expect(screen.getAllByRole('button', { name: /^Open / })).toHaveLength(1)
    expect(container.querySelectorAll('li')).toHaveLength(1)
  })

  it('a caller who only has hidden neighbours sees the count, not the empty state', async () => {
    api.get.mockResolvedValue({ total: 0, hidden_count: 1, groups: [] })
    render(wrap(<RelatedAssetsList assetId="a1" variant="summary" />))
    expect(await screen.findByText('1 related asset you can’t access')).toBeInTheDocument()
    expect(screen.queryByText('No related assets recorded.')).not.toBeInTheDocument()
  })

  it('never asks the API without assets:read or with the relationships module off', async () => {
    perms = []
    const { unmount } = render(wrap(<RelatedAssetsList assetId="a1" />))
    unmount()
    perms = ['assets:read']
    moduleOn = false
    render(wrap(<RelatedAssetsList assetId="a1" />))
    await new Promise((r) => setTimeout(r, 20))
    expect(api.get).not.toHaveBeenCalled()
  })
})

describe('RelatedAssetsList (summary)', () => {
  it('reads one line per group with up to three names and a way to the rest', async () => {
    api.get.mockResolvedValue(GROUPED)
    const onViewAll = vi.fn()
    render(wrap(<RelatedAssetsList assetId="a1" variant="summary" onViewAll={onViewAll} />))
    expect(await screen.findByText('Runs on')).toBeInTheDocument()
    expect(screen.getByText('cb-node-002')).toBeInTheDocument()
    expect(screen.queryByText('cb-node-003')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: '+217 more' }))
    expect(onViewAll).toHaveBeenCalled()
  })
})

describe('relationship verbs', () => {
  it('every registered relationship type reads in both directions, in English and Vietnamese', () => {
    const en = enAssets as Record<string, string>
    const vi = viAssets as Record<string, string>
    for (const type of ALL_RELATIONSHIP_TYPES) {
      for (const dir of ['outgoing', 'incoming'] as const) {
        const key = `assets.related.verb.${type}.${dir}`
        expect(RELATION_VERBS[type]?.[dir], key).toBeTruthy()
        expect(en[key], key).toBe(RELATION_VERBS[type][dir])
        expect(vi[key], key).toBeTruthy()
      }
    }
  })
})
