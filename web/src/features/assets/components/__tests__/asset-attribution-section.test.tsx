/**
 * The ownership section: what it shows for a CT name awaiting review and for
 * a legacy asset, that a decision PUTs and re-renders, and that people
 * without assets:write get no buttons.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'
import { AssetAttributionSection } from '../asset-attribution-section'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const api = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), post: vi.fn() }))
vi.mock('@/lib/api/client', () => api)

let perms: string[] = []
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: (p: string) => perms.includes(p) }) }
})

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const review = {
  state: 'needs_review',
  confidence: 85,
  reason: 'fqdn_under_asserted_root',
  recorded: true,
  human_decided: false,
  active_checks_allowed: false,
  evidence: [
    {
      rule: 'fqdn_under_asserted_root',
      technique: 'cert_transparency',
      source: 'crt.sh',
      weight: 0.85,
      observed: { root: 'listed.com' },
      first_observed_at: '2026-10-02T00:00:00Z',
      last_observed_at: '2026-10-02T00:00:00Z',
    },
  ],
}

beforeEach(() => {
  api.get.mockReset()
  api.put.mockReset()
  toast.success.mockReset()
  perms = ['assets:read', 'assets:write']
})

describe('AssetAttributionSection', () => {
  it('shows state, confidence, scan standing and evidence for a name awaiting review', async () => {
    api.get.mockResolvedValue(review)
    wrap(<AssetAttributionSection assetId="a1" />)
    expect(await screen.findByText('Needs review')).toBeInTheDocument()
    expect(screen.getByText('85% confidence')).toBeInTheDocument()
    expect(
      screen.getByText(/Scans skip this asset until its ownership is confirmed/)
    ).toBeInTheDocument()
    expect(
      screen.getByText(/Under listed.com, a domain you listed but have not verified/)
    ).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/v1/assets/a1/attribution')
  })

  it('a decision is PUT and the section shows the new state', async () => {
    api.get.mockResolvedValue(review)
    api.put.mockResolvedValue({
      ...review,
      state: 'confirmed',
      human_decided: true,
      active_checks_allowed: true,
    })
    wrap(<AssetAttributionSection assetId="a1" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Ours' }))
    expect(api.put).toHaveBeenCalledWith('/api/v1/assets/a1/attribution', { state: 'confirmed' })
    await waitFor(() => expect(screen.getByText('Confirmed')).toBeInTheDocument())
    expect(screen.getByText('Scans can reach this asset.')).toBeInTheDocument()
    expect(toast.success).toHaveBeenCalled()
  })

  it('a legacy asset reads as confirmed, without a confidence number', async () => {
    api.get.mockResolvedValue({
      state: 'confirmed',
      confidence: 100,
      recorded: false,
      human_decided: false,
      active_checks_allowed: true,
      evidence: [],
    })
    wrap(<AssetAttributionSection assetId="a1" />)
    expect(await screen.findByText('Confirmed')).toBeInTheDocument()
    expect(screen.queryByText(/confidence/)).not.toBeInTheDocument()
  })

  it('offers no decision without assets:write', async () => {
    perms = ['assets:read']
    api.get.mockResolvedValue(review)
    wrap(<AssetAttributionSection assetId="a1" />)
    await screen.findByText('Needs review')
    expect(screen.queryByRole('button', { name: 'Ours' })).not.toBeInTheDocument()
  })

  it('explains each decision next to its button', async () => {
    api.get.mockResolvedValue({ ...review, state: 'confirmed', human_decided: true })
    wrap(<AssetAttributionSection assetId="a1" />)
    const notOurs = await screen.findByRole('button', { name: 'Not ours' })
    expect(notOurs).toHaveAccessibleDescription(/leaves the inventory/)
    expect(
      screen.getByRole('button', { name: 'Ours, on third-party infrastructure' })
    ).toHaveAccessibleDescription(/passive and takeover checks/)
    expect(screen.getByRole('button', { name: 'Watch only' })).toHaveAccessibleDescription(
      /never actively scanned/
    )
    expect(screen.getByRole('button', { name: 'Undo the decision' })).toBeInTheDocument()
  })

  it('says confirming ownership is not a scope grant, and offers to add a scope entry', async () => {
    perms = ['assets:read', 'assets:write', 'attack_surface:scope:write']
    api.get.mockResolvedValue({
      ...review,
      state: 'confirmed',
      human_decided: true,
      active_checks_allowed: false,
      active_checks_blocked_by: 'out_of_scope',
      scope_status: 'out_of_scope',
      blocked_code: 'no_entry',
    })
    wrap(<AssetAttributionSection assetId="a1" assetName="promo.acme.io" />)
    expect(
      await screen.findByText('Out of scope: no scope entry covers this name.')
    ).toBeInTheDocument()
    expect(screen.getByText(/It does not authorize scanning/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Add to scope' }))
    expect(await screen.findByDisplayValue('promo.acme.io')).toBeInTheDocument()
  })

  it('names what covers an asset in scope', async () => {
    api.get.mockResolvedValue({
      ...review,
      state: 'confirmed',
      active_checks_allowed: true,
      scope_status: 'in_scope',
      covered_by: { kind: 'scope_target', pattern: '*.acme.io', proof: 'verified' },
    })
    wrap(<AssetAttributionSection assetId="a1" assetName="a.acme.io" />)
    expect(
      await screen.findByText('In scope through the scope entry *.acme.io (verified).')
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Add to scope' })).not.toBeInTheDocument()
  })
})
