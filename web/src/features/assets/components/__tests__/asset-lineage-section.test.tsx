/**
 * How this asset was found: the chain root first with links to visible
 * ancestors, a redacted ancestor as "Hidden asset" with no link, method and
 * confidence chips, and the root case.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'
import { AssetLineageSection } from '../asset-lineage-section'
import type { AssetLineage } from '../../lib/asset-lineage'

const api = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn() }))
vi.mock('@/lib/api/client', () => api)

vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: () => true }) }
})

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const chain: AssetLineage = {
  max_depth: 5,
  truncated: false,
  nodes: [
    {
      depth: 0,
      hidden: false,
      id: 'a1',
      name: 'charts-uat.example.com',
      type: 'subdomain',
      discovery_source: 'bruteforce',
      discovery_tool: 'dnsx',
      first_seen: '2026-10-29T10:00:00Z',
    },
    { depth: 1, hidden: true, via: 'parent' },
    {
      depth: 2,
      hidden: false,
      via: 'contains',
      id: 'root1',
      name: 'example.com',
      type: 'domain',
      discovery_source: 'manual',
    },
  ],
}

function serve(lineage: AssetLineage, confidence = 99) {
  api.get.mockImplementation((url?: string) => {
    if (!url) return Promise.resolve(undefined)
    if (url.endsWith('/lineage')) return Promise.resolve(lineage)
    if (url.endsWith('/attribution'))
      return Promise.resolve({
        state: 'discovered',
        confidence,
        recorded: true,
        human_decided: false,
        active_checks_allowed: false,
        evidence: [],
      })
    return Promise.resolve(undefined)
  })
}

describe('AssetLineageSection', () => {
  beforeEach(() => api.get.mockReset())

  it('shows the chain root first, links visible ancestors and redacts hidden ones', async () => {
    serve(chain)
    wrap(<AssetLineageSection assetId="a1" />)
    const list = await screen.findByRole('list', { name: 'Discovery chain' })
    const items = within(list).getAllByRole('listitem')
    expect(items).toHaveLength(3)
    expect(within(items[0]).getByRole('link', { name: 'example.com' })).toHaveAttribute(
      'href',
      '/assets/root1'
    )
    expect(within(items[1]).getByText('Hidden asset')).toBeInTheDocument()
    expect(within(items[1]).queryByRole('link')).toBeNull()
    expect(within(items[1]).getByText('Contains')).toBeInTheDocument()
    expect(within(items[2]).getByText('Parent of')).toBeInTheDocument()
    expect(within(items[2]).getByText('This asset')).toBeInTheDocument()
    expect(within(items[2]).queryByRole('link')).toBeNull()
  })

  it('shows the method and confidence chips of the asset', async () => {
    serve(chain, 87)
    wrap(<AssetLineageSection assetId="a1" />)
    expect(await screen.findByText('DNS brute force')).toBeInTheDocument()
    expect(screen.getByText('dnsx')).toBeInTheDocument()
    expect(await screen.findByText('87% confidence')).toBeInTheDocument()
  })

  it('says when the asset is a root', async () => {
    serve({ ...chain, nodes: [chain.nodes[0]] })
    wrap(<AssetLineageSection assetId="a1" />)
    expect(await screen.findByText(/No parent asset is recorded/)).toBeInTheDocument()
    expect(screen.queryByRole('list', { name: 'Discovery chain' })).toBeNull()
  })

  it('says when earlier steps are cut', async () => {
    serve({ ...chain, truncated: true })
    wrap(<AssetLineageSection assetId="a1" />)
    expect(
      await screen.findByText('Earlier steps are not shown (more than 5).')
    ).toBeInTheDocument()
  })
})
