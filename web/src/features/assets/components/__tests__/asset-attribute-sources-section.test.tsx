/**
 * Where an asset's values come from (RFC-069): the deciding source, the
 * other sources with their standing, the conflict badge, set-and-lock and
 * release, and no actions without assets:write.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'
import { AssetAttributeSourcesSection } from '../asset-attribute-sources-section'
import type { AttributeSourcesList } from '../../lib/attribute-sources'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const api = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn(), del: vi.fn(), post: vi.fn() }))
vi.mock('@/lib/api/client', () => api)

let perms: string[] = []
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: (p: string) => perms.includes(p) }) }
})

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const t = '2026-10-09T10:00:00Z'
const src = (kind: string, name: string, value: string, status: string) => ({
  kind,
  name,
  value,
  status,
  observed_at: t,
  ingested_at: t,
  confidence: 100,
})

const list: AttributeSourcesList = {
  attributes: [
    {
      attribute: 'criticality',
      value: 'critical',
      locked: false,
      conflict: true,
      decided_by: src('integration', 'defectdojo', 'critical', 'winner') as never,
      sources: [
        src('integration', 'defectdojo', 'critical', 'winner'),
        src('import', 'nessus', 'low', 'outranked'),
        src('scan', 'nmap', 'medium', 'untrusted'),
      ] as never,
    },
    {
      attribute: 'owner_ref',
      value: 'alice@example.com',
      locked: true,
      conflict: false,
      decided_by: src('manual', 'u1', 'alice@example.com', 'winner') as never,
      sources: [src('manual', 'u1', 'alice@example.com', 'winner')] as never,
    },
    {
      attribute: 'exposure',
      value: 'unknown',
      locked: false,
      conflict: false,
      decided_by: null,
      sources: [],
    },
    {
      attribute: 'data_classification',
      value: '',
      locked: false,
      conflict: false,
      decided_by: null,
      sources: [src('integration', 'cmdb', 'internal', 'stale')] as never,
    },
  ],
}

beforeEach(() => {
  api.get.mockReset()
  api.put.mockReset()
  api.del.mockReset()
  toast.success.mockReset()
  perms = ['assets:read', 'assets:write']
})

describe('AssetAttributeSourcesSection', () => {
  it('explains each value: deciding source, other sources, conflict and lock', async () => {
    api.get.mockResolvedValue(list)
    wrap(<AssetAttributeSourcesSection assetId="a1" />)
    const crit = await screen.findByRole('listitem', { name: 'Criticality' })
    expect(within(crit).getByText('2 sources disagree')).toBeInTheDocument()
    expect(within(crit).getByText(/Integration \(defectdojo\)/)).toBeInTheDocument()
    expect(within(crit).getByText(/Outranked/)).toBeInTheDocument()
    expect(within(crit).getByText(/Not trusted/)).toBeInTheDocument()

    const owner = screen.getByRole('listitem', { name: 'Owner reference' })
    expect(within(owner).getByText('Locked')).toBeInTheDocument()
    expect(within(owner).getByText(/Set by a person, locked until released/)).toBeInTheDocument()

    const exposure = screen.getByRole('listitem', { name: 'Exposure' })
    expect(within(exposure).getByText('No source has reported it')).toBeInTheDocument()

    const dc = screen.getByRole('listitem', { name: 'Data classification' })
    expect(within(dc).getByText('Not set')).toBeInTheDocument()
    expect(within(dc).getByText(/Stale/)).toBeInTheDocument()
    expect(
      within(dc).getByText('No trusted, current source: the value is kept')
    ).toBeInTheDocument()
  })

  it('releases a lock and sets and locks a value', async () => {
    api.get.mockResolvedValue(list)
    api.del.mockResolvedValue(list.attributes[1])
    api.put.mockResolvedValue(list.attributes[1])
    const user = userEvent.setup()
    wrap(<AssetAttributeSourcesSection assetId="a1" />)
    const owner = await screen.findByRole('listitem', { name: 'Owner reference' })
    await user.click(within(owner).getByRole('button', { name: /Release lock/ }))
    expect(api.del).toHaveBeenCalledWith('/api/v1/assets/a1/attribute-sources/owner_ref/lock')

    await user.click(within(owner).getByRole('button', { name: /Change locked value/ }))
    const input = within(owner).getByRole('textbox', { name: 'Owner reference value' })
    await user.clear(input)
    await user.type(input, 'bob@example.com')
    await user.click(within(owner).getByRole('button', { name: /Set and lock/ }))
    expect(api.put).toHaveBeenCalledWith('/api/v1/assets/a1/attribute-sources/owner_ref/lock', {
      value: 'bob@example.com',
    })
  })

  it('shows no actions without assets:write', async () => {
    perms = ['assets:read']
    api.get.mockResolvedValue(list)
    wrap(<AssetAttributeSourcesSection assetId="a1" />)
    await screen.findByRole('listitem', { name: 'Criticality' })
    expect(screen.queryByRole('button', { name: /lock/i })).not.toBeInTheDocument()
  })

  it('does not fetch without assets:read', () => {
    perms = []
    wrap(<AssetAttributeSourcesSection assetId="a1" />)
    expect(api.get).not.toHaveBeenCalled()
  })
})
