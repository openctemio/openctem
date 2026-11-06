/**
 * research/117 + research/425: the Decide panel shows each scope decision as
 * one card. The addresses behind in-scope names are grouped by network: one
 * decision per group, a selection or all waiting addresses, each after a
 * dialog listing exactly what changes; shared and CDN addresses are never in
 * a bulk add (only "Add anyway" on one address); "Is this network yours?" is
 * asked once per network; nothing is added without the person's click, and
 * nothing at all without scope write.
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
          ownership: { band: 'high', score: 90, signals: [] },
        },
        {
          asset_id: 'a2',
          address: '203.0.113.12',
          resolved_from: ['api.acme.example'],
          network: { known: true, asn: 'AS64500', org: 'Acme' },
          ownership: { band: 'low', score: 20, signals: [] },
        },
      ],
      prefix_rules: [{ prefix: '203.0.113.0/24', addresses: 1 }],
      groups: [
        {
          key: 'own_prefix:203.0.113.0/24',
          kind: 'own_prefix',
          prefix: '203.0.113.0/24',
          range: '203.0.113.0/24',
          addresses: ['203.0.113.10'],
          waiting: 1,
          checked: 0,
          resolved_from: ['www.acme.example'],
          evidence: [{ id: 'own_prefix', kind: 'anchor', count: 1 }],
        },
        {
          key: 'block:198.51.100.0/24',
          kind: 'block',
          prefix: '198.51.100.0/24',
          addresses: ['203.0.113.12'],
          waiting: 1,
          checked: 0,
          resolved_from: ['api.acme.example'],
          evidence: [{ id: 'new_address', kind: 'blocker', count: 1 }],
        },
        {
          key: 'other_network:AS7552',
          kind: 'other_network',
          asn: 'AS7552',
          org: 'Other Telecom',
          addresses: ['192.0.2.9'],
          waiting: 0,
          checked: 0,
          resolved_from: ['mail.acme.example'],
          ask_network: true,
          shared: true,
        },
        {
          key: 'provider:cloudflare|edge',
          kind: 'provider',
          provider: 'Cloudflare',
          addresses: ['104.16.5.5'],
          waiting: 0,
          checked: 0,
          resolved_from: ['cdn.acme.example'],
          shared: true,
        },
      ],
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
      {
        ...addr,
        count: 1,
        checked_count: 1,
        checked_addresses: known,
        prefix_rules: [],
        groups: addr.groups!.filter((g) => g.kind !== 'block'),
      },
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

const TITLE = '2 addresses your in-scope names resolve to'

describe('EASMDecidePanel', () => {
  it('groups the addresses by network with names and evidence, shared ones apart', async () => {
    api.get.mockImplementation(byUrl(cards(true)))
    wrap(<EASMDecidePanel />)
    expect(await screen.findByText(TITLE)).toBeInTheDocument()
    const groups = within(screen.getByTestId('decide-groups')).getAllByTestId('decide-group')
    expect(groups).toHaveLength(2)
    expect(groups[0]).toHaveTextContent('Your prefix 203.0.113.0/24')
    expect(groups[0]).toHaveTextContent('From www.acme.example')
    expect(groups[0]).toHaveTextContent('In your own prefix')
    expect(groups[1]).toHaveTextContent('198.51.100.0/24, network not known yet')
    expect(groups[1]).toHaveTextContent('No network data yet')
    expect(groups[1]).toHaveTextContent('New, first seen less than a day ago')
    // Another organization's network: asked once, never in a bulk add.
    const asked = screen.getByTestId('decide-asked-groups')
    expect(asked).toHaveTextContent('Is AS7552 Other Telecom your network?')
    // Shared: no decision needed, no group add button.
    const shared = screen.getByTestId('decide-shared-groups')
    expect(shared).toHaveTextContent('Cloudflare')
    expect(within(shared).queryByRole('button', { name: /^Add \d/ })).not.toBeInTheDocument()
    expect(screen.getByText('1 asset you confirmed is not in scope')).toBeInTheDocument()
    expect(api.post).not.toHaveBeenCalled()
  })

  it('the own prefix is one range entry, after a dialog that lists it', async () => {
    api.get.mockImplementation(byUrl(cards(true)))
    api.post.mockResolvedValue({ created: 1, pending: 0, existing: 0, refused: 0, items: [] })
    const user = userEvent.setup()
    wrap(<EASMDecidePanel />)
    await screen.findByText(TITLE)
    await user.click(screen.getByRole('button', { name: 'Add range 203.0.113.0/24' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(within(dialog).getByTestId('decide-confirm-items')).toHaveTextContent('203.0.113.0/24')
    expect(dialog).toHaveTextContent('does not prove the address is yours')
    await user.click(within(dialog).getByRole('button', { name: 'Add to scope' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1))
    expect(api.post).toHaveBeenCalledWith('/api/v1/easm/suggestions/addresses/add', {
      addresses: ['203.0.113.10'],
      ranges: ['203.0.113.0/24'],
      include_shared: false,
    })
  })

  it('Add all adds every waiting address in one decision and says names prove nothing', async () => {
    api.get.mockImplementation(byUrl(cards(true)))
    api.post.mockResolvedValue({ created: 2, pending: 0, existing: 0, refused: 0, items: [] })
    const user = userEvent.setup()
    wrap(<EASMDecidePanel />)
    await screen.findByText(TITLE)
    await user.click(screen.getByRole('button', { name: 'Add all (2)' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Add all 2 waiting addresses?')
    expect(dialog).toHaveTextContent('does not prove the address is yours')
    const items = within(dialog).getByTestId('decide-confirm-items')
    expect(items).toHaveTextContent('203.0.113.10')
    expect(items).toHaveTextContent('203.0.113.12')
    expect(items).not.toHaveTextContent('104.16.5.5')
    await user.click(within(dialog).getByRole('button', { name: 'Add to scope' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledTimes(1))
    expect(api.post.mock.calls[0][1].addresses).toEqual(['203.0.113.10', '203.0.113.12'])
  })

  it('selects across groups: Add selected and Not ours act on the selection', async () => {
    api.get.mockImplementation(byUrl(cards(true)))
    api.post.mockResolvedValue({ asset_ids: ['a1', 'a2'], addresses: [] })
    const user = userEvent.setup()
    wrap(<EASMDecidePanel />)
    await screen.findByText(TITLE)
    const boxes = screen.getAllByRole('checkbox', { name: /Select the addresses of/ })
    expect(boxes).toHaveLength(2) // shared groups are never selectable
    await user.click(boxes[0])
    await user.click(boxes[1])
    expect(screen.getByText('2 selected')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add selected' })).toBeInTheDocument()
    await user.click(
      within(screen.getByTestId('decide-groups-toolbar')).getByRole('button', { name: 'Not ours' })
    )
    const dialog = await screen.findByRole('alertdialog')
    await user.click(within(dialog).getByRole('button', { name: 'Not ours' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/easm/suggestions/addresses/reject', {
        addresses: ['203.0.113.10', '203.0.113.12'],
      })
    )
  })

  it('a shared address is only added on its own, with Add anyway', async () => {
    api.get.mockImplementation(byUrl(cards(true)))
    api.post.mockResolvedValue({ created: 1, pending: 0, existing: 0, refused: 0, items: [] })
    const user = userEvent.setup()
    wrap(<EASMDecidePanel />)
    await screen.findByText(TITLE)
    const shared = screen.getByTestId('decide-shared-groups')
    await user.click(within(shared).getByRole('button', { name: 'Show the address' }))
    await user.click(within(shared).getByRole('button', { name: 'Add 104.16.5.5 to scope' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('other organizations use it too')
    await user.click(within(dialog).getByRole('button', { name: 'Add to scope' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/easm/suggestions/addresses/add', {
        addresses: ['104.16.5.5'],
        ranges: [],
        include_shared: true,
      })
    )
  })

  it('is this network yours: Yes records it, No marks it not ours', async () => {
    api.get.mockImplementation(byUrl(cards(true)))
    api.post.mockResolvedValue({ kind: 'asn', value: 'AS7552', seed_id: 's1', auto_added: 0 })
    const user = userEvent.setup()
    wrap(<EASMDecidePanel />)
    await screen.findByText(TITLE)
    const q = screen.getByTestId('decide-network-question')
    await user.click(within(q).getByRole('button', { name: 'Yes, it is ours' }))
    let dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Record AS7552 Other Telecom as your network?')
    await user.click(within(dialog).getByRole('button', { name: 'Yes, it is ours' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/easm/suggestions/networks/ours', {
        key: 'other_network:AS7552',
      })
    )
    api.post.mockResolvedValue({
      kind: 'asn',
      value: 'AS7552',
      declined_id: 'd1',
      rejected: { asset_ids: ['a9'] },
    })
    await user.click(
      within(screen.getByTestId('decide-network-question')).getByRole('button', {
        name: 'No, not ours',
      })
    )
    dialog = await screen.findByRole('alertdialog')
    await user.click(within(dialog).getByRole('button', { name: 'No, not ours' }))
    await waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/api/v1/easm/suggestions/networks/not-ours', {
        key: 'other_network:AS7552',
      })
    )
  })

  it('offers no add without scope write', async () => {
    api.get.mockImplementation(byUrl(cards(false)))
    wrap(<EASMDecidePanel />)
    await screen.findByText(TITLE)
    expect(screen.queryByRole('button', { name: /^Add (all|range|\d)/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Yes, it is ours' })).not.toBeInTheDocument()
    expect(screen.getByText('Adding to scope needs permission to edit scope.')).toBeInTheDocument()
  })

  it('on the overview, Not now hides a card for this viewer', async () => {
    api.get.mockImplementation(byUrl(cards(true)))
    const user = userEvent.setup()
    wrap(<EASMDecidePanel compact />)
    await screen.findByText(TITLE)
    await user.click(screen.getAllByRole('button', { name: 'Not now' })[0])
    await waitFor(() => expect(screen.queryByText(TITLE)).not.toBeInTheDocument())
    expect(screen.getByText('1 asset you confirmed is not in scope')).toBeInTheDocument()
  })

  it('while unclassified assets get checks, the checked ones need no decision', async () => {
    api.get.mockImplementation(byUrl(checkedCards(true)))
    wrap(<EASMDecidePanel />)
    expect(await screen.findByText('1 address your in-scope names resolve to')).toBeInTheDocument()
    expect(screen.getByTestId('decide-no-decision')).toHaveTextContent(
      '1 address already gets low-impact checks.'
    )
  })

  it('a card that offers nothing is not a decision: empty state, the shared list quietly', async () => {
    const addr = cards(true).cards[0]
    const body = {
      can_add: true,
      total: 0,
      name_rules: 0,
      cards: [
        {
          ...addr,
          count: 0,
          addresses: [],
          groups: addr.groups!.filter((g) => g.shared),
        },
      ],
    }
    api.get.mockImplementation(byUrl(body))
    wrap(<EASMDecidePanel />)
    expect(await screen.findByText('Nothing to decide')).toBeInTheDocument()
    expect(screen.queryByTestId('decide-card-addresses')).not.toBeInTheDocument()
    expect(screen.getByTestId('decide-no-decision')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Add (all|range|\d)/ })).not.toBeInTheDocument()
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

  it('a snoozed card comes back when it shows something new', async () => {
    api.get.mockImplementation(byUrl(cards(true)))
    const user = userEvent.setup()
    const { unmount } = wrap(<EASMDecidePanel compact />)
    await screen.findByText(TITLE)
    await user.click(screen.getAllByRole('button', { name: 'Not now' })[0])
    await waitFor(() => expect(screen.queryByText(TITLE)).not.toBeInTheDocument())
    unmount()
    const changed = cards(true)
    changed.cards[0].addresses![0].ports = [22, 443, 3389]
    api.get.mockImplementation(byUrl(changed))
    wrap(<EASMDecidePanel compact />)
    expect(await screen.findByText(TITLE)).toBeInTheDocument()
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
    api.get.mockImplementation(byUrl(cards(true)))
    api.post.mockResolvedValueOnce({ asset_ids: ['a1'], addresses: ['203.0.113.10'] })
    const user = userEvent.setup()
    wrap(<EASMDecidePanel />)
    await screen.findByText(TITLE)
    const group = within(screen.getByTestId('decide-groups')).getAllByTestId('decide-group')[0]
    await user.click(within(group).getByRole('button', { name: 'Not ours' }))
    const dialog = await screen.findByRole('alertdialog')
    await user.click(within(dialog).getByRole('button', { name: 'Not ours' }))
    await waitFor(() => expect(toast.success).toHaveBeenCalled())
    const action = (toast.success as ReturnType<typeof vi.fn>).mock.calls.at(-1)?.[1].action
    api.post.mockRejectedValueOnce(new Error('boom'))
    action.onClick()
    await waitFor(() => expect(toast.error).toHaveBeenCalled())
  })
})
