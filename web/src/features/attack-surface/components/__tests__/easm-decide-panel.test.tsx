/**
 * research/117: the Decide panel shows each scope decision as one card.
 * Addresses behind in-scope names are offered as one bulk add of exact
 * entries; shared or CDN addresses are listed apart with no button; an
 * unknown network is said, never implied safe; nothing is added without the
 * person's click, and nothing at all without scope write.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: () => true }), useHasPermission: () => true }
})
vi.mock('sonner', () => ({
  toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn(), info: vi.fn() },
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))

const { EASMDecidePanel } = await import('../easm-decide-panel')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const cards = (canAdd: boolean) => ({
  can_add: canAdd,
  total: 2,
  cards: [
    {
      kind: 'addresses_behind_names',
      count: 2,
      names_count: 3,
      unknown_network_count: 1,
      shared_count: 1,
      addresses: [
        {
          asset_id: 'a1',
          address: '203.0.113.10',
          resolved_from: ['www.acme.example'],
          network: { known: false },
        },
        {
          asset_id: 'a2',
          address: '203.0.113.12',
          resolved_from: ['api.acme.example'],
          network: { known: true, asn: 'AS64500', org: 'Acme' },
        },
      ],
      shared_addresses: [
        {
          asset_id: 'a3',
          address: '104.16.5.5',
          resolved_from: ['cdn.acme.example'],
          network: { known: true, provider: 'Cloudflare' },
          shared: 'edge_range',
        },
      ],
    },
    {
      kind: 'confirmed_out_of_scope',
      count: 1,
      assets: [{ asset_id: 'c1', name: 'old.acme.example', target_type: 'domain' }],
    },
  ],
})

const byUrl = (body: unknown) => (url: string) =>
  Promise.resolve(
    url.includes('/candidates/suggestions') ? { suggestions: [], individual: [] } : body
  )

beforeEach(() => {
  api.get.mockReset()
  api.post.mockReset()
  window.localStorage.clear()
})

describe('EASMDecidePanel', () => {
  it('groups the addresses into one card and says what is unknown and what is left out', async () => {
    api.get.mockImplementation(byUrl(cards(true)))
    const user = userEvent.setup()
    wrap(<EASMDecidePanel />)
    expect(
      await screen.findByText('2 addresses your in-scope names resolve to')
    ).toBeInTheDocument()
    expect(screen.getByText('Network unknown for 1: check it is yours')).toBeInTheDocument()
    expect(screen.getByText('1 shared or CDN address left out')).toBeInTheDocument()
    expect(screen.getByText('1 asset you confirmed is not in scope')).toBeInTheDocument()
    await user.click(screen.getAllByRole('button', { name: 'View list' })[0])
    expect(screen.getByText('Network unknown')).toBeInTheDocument()
    expect(screen.getByText('CDN edge range (Cloudflare)')).toBeInTheDocument()
    expect(api.post).not.toHaveBeenCalled()
  })

  it('adds exactly the offered addresses on a click, never the shared ones', async () => {
    api.get.mockImplementation(byUrl(cards(true)))
    api.post.mockResolvedValue({ created: 2, existing: 0, refused: 0, results: [] })
    const user = userEvent.setup()
    wrap(<EASMDecidePanel />)
    await screen.findByText('2 addresses your in-scope names resolve to')
    await user.click(screen.getAllByRole('button', { name: 'Add 2 to scope' })[0])
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1))
    const [url, body] = api.post.mock.calls[0]
    expect(url).toBe('/api/v1/scope/targets/bulk')
    expect(body.items).toEqual([
      { target_type: 'ip_address', pattern: '203.0.113.10' },
      { target_type: 'ip_address', pattern: '203.0.113.12' },
    ])
    expect(body.reason).toContain('www.acme.example')
  })

  it('offers no add without scope write', async () => {
    api.get.mockImplementation(byUrl(cards(false)))
    wrap(<EASMDecidePanel />)
    await screen.findByText('2 addresses your in-scope names resolve to')
    expect(screen.queryByRole('button', { name: /Add \d to scope/ })).not.toBeInTheDocument()
    expect(screen.getByText('Adding to scope needs permission to edit scope.')).toBeInTheDocument()
  })

  it('on the overview, Not now hides a card for this viewer', async () => {
    api.get.mockImplementation(byUrl(cards(true)))
    const user = userEvent.setup()
    wrap(<EASMDecidePanel compact />)
    await screen.findByText('2 addresses your in-scope names resolve to')
    await user.click(screen.getAllByRole('button', { name: 'Not now' })[0])
    await waitFor(() =>
      expect(
        screen.queryByText('2 addresses your in-scope names resolve to')
      ).not.toBeInTheDocument()
    )
    expect(screen.getByText('1 asset you confirmed is not in scope')).toBeInTheDocument()
  })
})
