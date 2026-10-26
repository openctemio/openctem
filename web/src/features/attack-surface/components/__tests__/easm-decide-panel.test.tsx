/**
 * research/117: the Decide panel shows each scope decision as one card.
 * Addresses behind in-scope names are offered as one bulk add of exact
 * entries; shared or CDN addresses need no decision and are one quiet line
 * (never with ports, never counted); an
 * unknown network is said, never implied safe; nothing is added without the
 * person's click, and nothing at all without scope write.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
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
const { toast } = await import('sonner')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const cards = (canAdd: boolean) => ({
  can_add: canAdd,
  total: 2,
  name_rules: 0,
  cards: [
    {
      kind: 'addresses_behind_names',
      count: 2,
      names_count: 3,
      unknown_network_count: 1,
      shared_count: 1,
      provider_count: 1,
      providers: [{ provider: 'Cloudflare', class: 'edge', addresses: 1 }],
      addresses: [
        {
          asset_id: 'a1',
          address: '203.0.113.10',
          resolved_from: ['www.acme.example'],
          network: { known: false },
          ports: [22, 443],
          other_names: ['old.acme.example'],
          prefix: '203.0.113.0/24',
        },
        {
          asset_id: 'a2',
          address: '203.0.113.12',
          resolved_from: ['api.acme.example'],
          network: { known: true, asn: 'AS64500', org: 'Acme' },
        },
      ],
      prefix_rules: [{ prefix: '203.0.113.0/24', addresses: 1 }],
      shared_addresses: [
        {
          asset_id: 'a3',
          address: '104.16.5.5',
          resolved_from: ['cdn.acme.example'],
          network: { known: true, provider: 'Cloudflare', class: 'edge' },
          shared: 'edge_range',
          ports: [80, 443, 8080, 8443],
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

/** The server's split while unclassified assets get checks: the known network is checked. */
const checkedCards = (canAdd: boolean) => {
  const c = cards(canAdd)
  const addr = c.cards[0]
  const known = addr.addresses!.splice(1, 1)
  return {
    ...c,
    cards: [
      { ...addr, count: 1, checked_count: 1, checked_addresses: known, prefix_rules: [] },
      c.cards[1],
    ],
  }
}

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
    expect(screen.getByText('1 asset you confirmed is not in scope')).toBeInTheDocument()
    await user.click(screen.getAllByRole('button', { name: 'View list' })[0])
    expect(screen.getByText('Network unknown')).toBeInTheDocument()
    // The shared address is not on the card: one quiet line, its own list.
    expect(screen.queryByText('CDN edge range (Cloudflare)')).not.toBeInTheDocument()
    const note = screen.getByTestId('decide-no-decision')
    expect(note).toHaveTextContent(
      '1 address your names resolve to belongs to Cloudflare and needs no decision.'
    )
    await user.click(within(note).getByRole('button', { name: 'View list' }))
    expect(within(note).getByText('CDN edge range (Cloudflare)')).toBeInTheDocument()
    // The edge's ports are the provider's: never shown.
    expect(within(note).queryByText(/Open ports seen/)).not.toBeInTheDocument()
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

  it('shows what was seen on each address and offers the own prefix as one rule', async () => {
    api.get.mockImplementation(byUrl(cards(true)))
    api.post.mockResolvedValue({ created: 1, existing: 0, refused: 0, results: [] })
    const user = userEvent.setup()
    wrap(<EASMDecidePanel />)
    await screen.findByText('2 addresses your in-scope names resolve to')
    expect(screen.getByText(/Today only the names are scanned/)).toBeInTheDocument()
    await user.click(screen.getAllByRole('button', { name: 'View list' })[0])
    expect(screen.getByText(/Open ports seen: 22, 443/)).toBeInTheDocument()
    expect(screen.getByText(/Also named old.acme.example \(not in scope\)/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Add 203.0.113.0/24' }))
    await user.click(screen.getByRole('button', { name: 'Add to scope' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1))
    expect(api.post.mock.calls[0][1].items).toEqual([
      { target_type: 'cidr', pattern: '203.0.113.0/24' },
    ])
  })

  it('while unclassified assets get checks, only unknown networks wait for a decision', async () => {
    api.get.mockImplementation(byUrl(checkedCards(true)))
    const user = userEvent.setup()
    wrap(<EASMDecidePanel />)
    expect(await screen.findByText('1 address your in-scope names resolve to')).toBeInTheDocument()
    // One on the addresses card, one on the confirmed-assets card.
    expect(screen.getAllByRole('button', { name: 'Add 1 to scope' })).toHaveLength(2)
    const note = screen.getByTestId('decide-no-decision')
    expect(note).toHaveTextContent('1 address already gets low-impact checks.')
    await user.click(within(note).getByRole('button', { name: 'View list' }))
    expect(
      within(note).getByText('Already get low-impact checks (add to scope for a full scan)')
    ).toBeInTheDocument()
  })

  it('a card that offers nothing is not a decision: empty state, one quiet line', async () => {
    const onlyShared = cards(true)
    const addr = onlyShared.cards[0]
    const body = {
      can_add: true,
      total: 0,
      name_rules: 0,
      cards: [{ ...addr, count: 0, addresses: [], prefix_rules: [], unknown_network_count: 0 }],
    }
    api.get.mockImplementation(byUrl(body))
    wrap(<EASMDecidePanel />)
    expect(await screen.findByText('Nothing to decide')).toBeInTheDocument()
    expect(screen.queryByTestId('decide-card-addresses')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Add \d to scope/ })).not.toBeInTheDocument()
    expect(screen.getByTestId('decide-no-decision')).toBeInTheDocument()
  })

  it('on the overview, a card that offers nothing is not shown', async () => {
    const addr = cards(true).cards[0]
    api.get.mockImplementation(
      byUrl({
        can_add: true,
        total: 0,
        name_rules: 0,
        cards: [{ ...addr, count: 0, addresses: [] }],
      })
    )
    const { container } = wrap(<EASMDecidePanel compact />)
    await waitFor(() => expect(api.get).toHaveBeenCalled())
    await new Promise((r) => setTimeout(r, 20))
    expect(container).toBeEmptyDOMElement()
  })

  it('Not ours records a rejection of the waiting addresses only', async () => {
    api.get.mockImplementation(byUrl(checkedCards(true)))
    api.post.mockResolvedValue({ decided: [{ asset_id: 'a1' }], not_found: [] })
    const user = userEvent.setup()
    wrap(<EASMDecidePanel />)
    await screen.findByText('1 address your in-scope names resolve to')
    await user.click(screen.getByRole('button', { name: 'Not ours' }))
    const dialog = await screen.findByRole('alertdialog').catch(() => screen.findByRole('dialog'))
    await user.click(within(dialog).getByRole('button', { name: 'Not ours' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/easm/candidates/decisions', {
        asset_ids: ['a1'],
        state: 'rejected',
      })
    )
  })

  it('a snoozed card comes back when it shows something new', async () => {
    api.get.mockImplementation(byUrl(cards(true)))
    const user = userEvent.setup()
    const { unmount } = wrap(<EASMDecidePanel compact />)
    await screen.findByText('2 addresses your in-scope names resolve to')
    await user.click(screen.getAllByRole('button', { name: 'Not now' })[0])
    await waitFor(() =>
      expect(
        screen.queryByText('2 addresses your in-scope names resolve to')
      ).not.toBeInTheDocument()
    )
    unmount()
    const changed = cards(true)
    changed.cards[0].addresses![0].ports = [22, 443, 3389]
    api.get.mockImplementation(byUrl(changed))
    wrap(<EASMDecidePanel compact />)
    expect(
      await screen.findByText('2 addresses your in-scope names resolve to')
    ).toBeInTheDocument()
  })

  it('on the overview, only name rules waiting is one line with a link, not a panel', async () => {
    api.get.mockImplementation(byUrl({ can_add: true, total: 3, name_rules: 3, cards: [] }))
    wrap(<EASMDecidePanel compact />)
    const line = await screen.findByTestId('decide-rules-line')
    expect(line).toHaveTextContent('3 name rules waiting')
    expect(within(line).getByRole('link', { name: 'Review' })).toHaveAttribute(
      'href',
      '/attack-surface/review'
    )
  })

  it('on the overview, nothing is rendered while loading and when nothing waits', async () => {
    api.get.mockImplementation(() => new Promise(() => {}))
    const { container } = wrap(<EASMDecidePanel compact />)
    expect(container.querySelector('[class*="animate-pulse"]')).toBeNull()
    expect(container).toBeEmptyDOMElement()
  })

  it('a failed Undo of Not ours says so', async () => {
    api.get.mockImplementation(byUrl(checkedCards(true)))
    api.post.mockResolvedValueOnce({ decided: [{ asset_id: 'a1' }], not_found: [] })
    const user = userEvent.setup()
    wrap(<EASMDecidePanel />)
    await screen.findByText('1 address your in-scope names resolve to')
    await user.click(screen.getByRole('button', { name: 'Not ours' }))
    const dialog = await screen.findByRole('alertdialog').catch(() => screen.findByRole('dialog'))
    await user.click(within(dialog).getByRole('button', { name: 'Not ours' }))
    await waitFor(() => expect(toast.success).toHaveBeenCalled())
    const action = (toast.success as ReturnType<typeof vi.fn>).mock.calls.at(-1)?.[1].action
    api.post.mockRejectedValueOnce(new Error('boom'))
    action.onClick()
    await waitFor(() => expect(toast.error).toHaveBeenCalled())
  })
})

describe('EASMDecidePanel provider line', () => {
  it('names several providers and counts the other shared addresses apart', async () => {
    const c = cards(true)
    const addr = c.cards[0]
    api.get.mockImplementation(
      byUrl({
        ...c,
        cards: [
          {
            ...addr,
            shared_count: 5,
            provider_count: 4,
            providers: [
              { provider: 'Cloudflare', class: 'edge', addresses: 3 },
              { provider: 'Vercel', class: 'saas_hosting', addresses: 1 },
            ],
          },
          c.cards[1],
        ],
      })
    )
    wrap(<EASMDecidePanel />)
    const note = await screen.findByTestId('decide-no-decision')
    expect(note).toHaveTextContent(
      '4 addresses your names resolve to belong to CDN or hosting providers (Cloudflare, Vercel) and need no decision.'
    )
    expect(note).toHaveTextContent('1 more is shared with other organizations and is not offered.')
  })
})
