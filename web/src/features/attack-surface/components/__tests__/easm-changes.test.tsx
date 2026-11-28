/**
 * Attack surface › Changes (RFC-080): counts per kind, a kind filter that
 * reaches the API, the digest window from the URL, and nothing fetched
 * without assets:read.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const perms = vi.hoisted(() => ({ read: true }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: () => perms.read }) }
})

const { EASMChanges } = await import('../easm-changes')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

type Item = { id: string; kind: string; asset_id?: string; [k: string]: unknown }
const grouped = (items: Item[], count = 1) =>
  items.map((c) => ({
    key: { kind: c.kind, detail: '', asset_id: c.asset_id },
    count,
    latest: c,
  }))

const changes: Item[] = [
  {
    id: 'x1',
    kind: 'dns_dangling',
    at: '2026-10-10T00:00:00Z',
    asset_name: 'old.example.com',
    asset_id: '0198f0e2-0000-7000-8000-0000000000a1',
    severity: 'medium',
    new: 'Dangling CNAME',
    exposure_id: 'x1',
  },
  {
    id: 'h1',
    kind: 'host_added',
    at: '2026-10-09T00:00:00Z',
    asset_name: 'new.example.com',
    asset_id: '0198f0e2-0000-7000-8000-0000000000a2',
  },
]

const page = {
  from: '2026-10-04T00:00:00Z',
  to: '2026-10-11T00:00:00Z',
  total: 3,
  counts: { host_added: 2, dns_dangling: 1 },
  items: [],
  groups: grouped(changes),
}

beforeEach(() => {
  api.get.mockReset().mockResolvedValue(page)
  perms.read = true
  window.history.replaceState(null, '', '/attack-surface/changes')
})

describe('EASMChanges', () => {
  it('lists changes and shows the count of each kind in the Kind menu', async () => {
    wrap(<EASMChanges />)
    expect(await screen.findByText('old.example.com')).toBeInTheDocument()
    expect(screen.getByText('new.example.com')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'new.example.com' })).toHaveAttribute(
      'href',
      '/assets/0198f0e2-0000-7000-8000-0000000000a2'
    )
    await userEvent.click(screen.getByRole('button', { name: /Change kinds/ }))
    expect(await screen.findByRole('menuitemradio', { name: /New host\s*2/ })).toBeInTheDocument()
    expect(screen.getByRole('menuitemradio', { name: /Dangling DNS\s*1/ })).toBeInTheDocument()
  })

  it('filters by kind through the API and shows the kind as a removable chip', async () => {
    wrap(<EASMChanges />)
    await screen.findByText('old.example.com')
    await userEvent.click(screen.getByRole('button', { name: /Change kinds/ }))
    await userEvent.click(await screen.findByRole('menuitemradio', { name: /Dangling DNS/ }))
    const last = api.get.mock.calls.at(-1)?.[0] as string
    expect(new URL(last, 'http://x').searchParams.get('kind')).toBe('dns_dangling')
    await userEvent.click(await screen.findByRole('button', { name: 'Remove filter Dangling DNS' }))
    const after = api.get.mock.calls.at(-1)?.[0] as string
    expect(new URL(after, 'http://x').searchParams.get('kind')).toBeNull()
  })

  it('uses the digest window from the link', async () => {
    window.history.replaceState(
      null,
      '',
      '/attack-surface/changes?from=2026-10-05T08:00:00Z&to=2026-10-12T08:00:00Z'
    )
    wrap(<EASMChanges />)
    await screen.findByText('old.example.com')
    const url = new URL(api.get.mock.calls[0][0] as string, 'http://x')
    expect(url.searchParams.get('from')).toBe('2026-10-05T08:00:00.000Z')
    expect(url.searchParams.get('to')).toBe('2026-10-12T08:00:00.000Z')
    expect(screen.getByRole('button', { name: 'Back to recent changes' })).toBeInTheDocument()
  })

  it('fetches nothing without assets:read', async () => {
    perms.read = false
    wrap(<EASMChanges />)
    expect(await screen.findByText('Access denied')).toBeInTheDocument()
    expect(api.get).not.toHaveBeenCalled()
  })

  it('shows an unknown kind as itself, neutral, never as a new exposure', async () => {
    api.get.mockResolvedValue({
      ...page,
      groups: grouped([
        {
          id: 'u1',
          kind: 'brand_new_kind',
          at: '2026-10-10T00:00:00Z',
          asset_name: 'x.example.com',
        },
      ]),
    })
    wrap(<EASMChanges />)
    await screen.findByText('x.example.com')
    // A kind this build does not know is shown as a neutral "Other change", never as the raw
    // enum value (the wording pass hides codes on purpose).
    expect(screen.getByText('Other change')).toBeInTheDocument()
    expect(screen.queryByText('brand new kind')).not.toBeInTheDocument()
    expect(screen.queryByText('brand_new_kind')).not.toBeInTheDocument()
    expect(within(screen.getByRole('list')).queryByText('New exposure')).not.toBeInTheDocument()
  })

  it('links the exposure title and uses the shared severity badge', async () => {
    wrap(<EASMChanges />)
    const link = await screen.findByRole('link', { name: 'Dangling CNAME' })
    expect(link).toHaveAttribute('href', '/exposures?state=all&q=Dangling%20CNAME')
    expect(screen.getByText('Medium')).toBeInTheDocument()
  })

  it('folds the same change on one asset into one row and opens all of them over the page', async () => {
    const lookalike = (id: string, name: string) => ({
      id,
      kind: 'exposure_new',
      at: '2026-10-10T00:00:00Z',
      asset_name: 'example.com',
      asset_id: '0198f0e2-0000-7000-8000-0000000000b1',
      detail: 'lookalike_domain',
      severity: 'low',
      new: `Lookalike domain registered: ${name}`,
      exposure_id: id,
    })
    api.get.mockImplementation(async (url: string) => {
      const q = new URL(url, 'http://x').searchParams
      if (q.get('group_kind')) {
        return {
          ...page,
          total: 474,
          groups: undefined,
          items: [lookalike('l1', 'eaxmple.com'), lookalike('l2', 'examp1e.com')],
        }
      }
      return {
        ...page,
        total: 474,
        groups: [
          {
            key: {
              kind: 'exposure_new',
              detail: 'lookalike_domain',
              asset_id: '0198f0e2-0000-7000-8000-0000000000b1',
            },
            count: 474,
            latest: lookalike('l1', 'eaxmple.com'),
          },
        ],
      }
    })
    wrap(<EASMChanges />)
    // One row, not 474.
    expect(await screen.findAllByText('example.com')).toHaveLength(1)
    const first = new URL(api.get.mock.calls[0][0] as string, 'http://x')
    expect(first.searchParams.get('grouped')).toBe('true')
    await userEvent.click(screen.getByRole('button', { name: 'Show all 474 changes' }))
    const dialog = await screen.findByRole('dialog')
    expect(
      await within(dialog).findByText('Lookalike domain registered: examp1e.com')
    ).toBeInTheDocument()
    const groupCall = new URL(api.get.mock.calls.at(-1)?.[0] as string, 'http://x')
    expect(groupCall.searchParams.get('group_kind')).toBe('exposure_new')
    expect(groupCall.searchParams.get('group_detail')).toBe('lookalike_domain')
    expect(groupCall.searchParams.get('group_asset')).toBe('0198f0e2-0000-7000-8000-0000000000b1')
    expect(groupCall.searchParams.get('grouped')).toBeNull()
    // The sheet reads the same window as the page.
    expect(groupCall.searchParams.get('from')).toBe('2026-10-04T00:00:00Z')
  })
})
