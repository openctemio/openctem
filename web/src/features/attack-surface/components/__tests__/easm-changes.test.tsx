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

const page = {
  from: '2026-10-04T00:00:00Z',
  to: '2026-10-11T00:00:00Z',
  total: 3,
  counts: { host_added: 2, dns_dangling: 1 },
  items: [
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
  ],
}

beforeEach(() => {
  api.get.mockReset().mockResolvedValue(page)
  perms.read = true
  window.history.replaceState(null, '', '/attack-surface/changes')
})

describe('EASMChanges', () => {
  it('lists changes with the count of each kind', async () => {
    wrap(<EASMChanges />)
    expect(await screen.findByText('old.example.com')).toBeInTheDocument()
    expect(screen.getByText('new.example.com')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /New host\s*2/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Dangling DNS\s*1/ })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'new.example.com' })).toHaveAttribute(
      'href',
      '/assets/0198f0e2-0000-7000-8000-0000000000a2'
    )
  })

  it('filters by kind through the API', async () => {
    wrap(<EASMChanges />)
    await screen.findByText('old.example.com')
    await userEvent.click(screen.getByRole('button', { name: /Dangling DNS/ }))
    const last = api.get.mock.calls.at(-1)?.[0] as string
    expect(new URL(last, 'http://x').searchParams.get('kind')).toBe('dns_dangling')
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
      items: [
        {
          id: 'u1',
          kind: 'brand_new_kind',
          at: '2026-10-10T00:00:00Z',
          asset_name: 'x.example.com',
        },
      ],
    })
    wrap(<EASMChanges />)
    await screen.findByText('x.example.com')
    expect(screen.getByText('brand new kind')).toBeInTheDocument()
    expect(within(screen.getByRole('list')).queryByText('New exposure')).not.toBeInTheDocument()
  })

  it('links the exposure title and uses the shared severity badge', async () => {
    wrap(<EASMChanges />)
    const link = await screen.findByRole('link', { name: 'Dangling CNAME' })
    expect(link).toHaveAttribute('href', '/exposures?state=all&q=Dangling%20CNAME')
    expect(screen.getByText('Medium')).toBeInTheDocument()
  })

  it('marks a selected kind without the primary button style, and has no duplicate description', async () => {
    wrap(<EASMChanges />)
    await screen.findByText('old.example.com')
    const chip = screen.getByRole('button', { name: /Dangling DNS/ })
    await userEvent.click(chip)
    expect(chip).toHaveAttribute('aria-pressed', 'true')
    expect(chip.className).not.toContain('bg-primary')
    expect(screen.queryByText(/Only assets you can see are listed/)).not.toBeInTheDocument()
  })
})
