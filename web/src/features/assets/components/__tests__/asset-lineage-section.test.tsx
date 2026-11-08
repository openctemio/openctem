/**
 * How we found this asset: the method and confidence from the lineage, the
 * chain from the story (root first, visible ancestors linked, a hidden one
 * with no name or link), and the root case.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'
import { AssetLineageSection } from '../asset-lineage-section'
import type { AssetLineage } from '../../lib/asset-lineage'
import type { Story } from '@/features/exploration/lib/story'

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

const story: Story = {
  subject: { kind: 'asset', id: 'a1' },
  hidden: 1,
  truncated: false,
  more_reports: 0,
  max_steps: 16,
  steps: [
    {
      kind: 'scope_entry',
      hidden: false,
      scope_entry: { id: 's1', target_type: 'domain', pattern: '*.example.com', asset_id: 'a1' },
    },
    {
      kind: 'asset',
      hidden: false,
      asset: { id: 'root1', name: 'example.com', type: 'domain', via: 'contains' },
    },
    { kind: 'asset', hidden: true, asset: { via: 'parent' } },
    {
      kind: 'asset',
      hidden: false,
      asset: { id: 'a1', name: 'charts-uat.example.com', type: 'subdomain', subject: true },
    },
  ],
}

function serve(lineage: AssetLineage, confidence = 99, s: Story = story) {
  api.get.mockImplementation((url?: string) => {
    if (!url) return Promise.resolve(undefined)
    if (url.endsWith('/lineage')) return Promise.resolve(lineage)
    if (url.endsWith('/story')) return Promise.resolve(s)
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

  it('shows the story chain root first, links visible steps and hides the rest', async () => {
    serve(chain)
    wrap(<AssetLineageSection assetId="a1" />)
    const list = await screen.findByRole('list', { name: 'How we found this' })
    const items = within(list).getAllByRole('listitem')
    expect(items).toHaveLength(4)
    expect(within(items[0]).getByRole('link', { name: '*.example.com' })).toHaveAttribute(
      'href',
      '/scope?tab=in&q=*.example.com'
    )
    expect(within(items[1]).getByRole('link', { name: 'example.com' })).toHaveAttribute(
      'href',
      '/assets/root1'
    )
    expect(within(items[2]).getByText('A step you cannot see')).toBeInTheDocument()
    expect(within(items[2]).queryByRole('link')).toBeNull()
    expect(within(items[2]).getByText('Contains')).toBeInTheDocument()
    expect(within(items[3]).getByText('Parent of')).toBeInTheDocument()
    expect(within(items[3]).getByText('This asset')).toBeInTheDocument()
    expect(within(items[3]).queryByRole('link')).toBeNull()
  })

  it('shows the method and confidence chips of the asset', async () => {
    serve(chain, 87)
    wrap(<AssetLineageSection assetId="a1" />)
    expect(await screen.findByText('DNS brute force')).toBeInTheDocument()
    expect(screen.getByText('dnsx')).toBeInTheDocument()
    expect(await screen.findByText('87% confidence')).toBeInTheDocument()
  })

  it('says when the asset is a root', async () => {
    serve({ ...chain, nodes: [chain.nodes[0]] }, 99, {
      ...story,
      steps: [story.steps[3]],
      hidden: 0,
    })
    wrap(<AssetLineageSection assetId="a1" />)
    expect(await screen.findByText(/No parent asset is recorded/)).toBeInTheDocument()
  })

  it('says when earlier steps are cut', async () => {
    serve({ ...chain, truncated: true }, 99, { ...story, truncated: true })
    wrap(<AssetLineageSection assetId="a1" />)
    expect(await screen.findByText('Earlier steps are not shown.')).toBeInTheDocument()
  })
})
