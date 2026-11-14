/**
 * The card of a selected graph group names its first members (up to five)
 * with "and N more", each one opening the asset, and shows only what the
 * relationship groups endpoint returned for that group: no name the server
 * did not send, none from another group, and a plain note when the caller
 * may see none of them.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'
import {
  ClusterMembers,
  clusterPreviewItems,
  CLUSTER_PREVIEW,
} from '../relationships/cluster-members'
import type { RelatedAssetItem, RelatedAssetsResponse } from '../../hooks/use-related-assets'
import type { GraphClusterNode } from '../../lib/neighborhood-graph'
import enAssets from '@/lib/i18n/dictionaries/en/assets.json'
import viAssets from '@/lib/i18n/dictionaries/vi/assets.json'

const api = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('@/lib/api/client', () => api)

function item(
  id: string,
  name: string,
  type: RelatedAssetItem['type'] = 'resolves_to',
  direction: RelatedAssetItem['direction'] = 'incoming'
): RelatedAssetItem {
  return {
    relationship_id: `rel-${id}`,
    type,
    direction,
    asset: { id, name, type: 'subdomain' },
    discovery_method: 'automatic',
    confidence: 'high',
    is_control_plane: false,
    created_at: '2026-11-01T00:00:00Z',
  }
}

const cluster: GraphClusterNode = {
  kind: 'cluster',
  id: 'cluster:ip-1:resolves_to:incoming',
  anchor: 'ip-1',
  relType: 'resolves_to',
  direction: 'incoming',
  remaining: 22,
  byType: { subdomain: 22 },
  offset: 0,
}

const names = [...Array(5)].map((_, i) => `host-${i + 1}.example.com`)

function response(items: RelatedAssetItem[], total: number, hidden = 0): RelatedAssetsResponse {
  return {
    total,
    hidden_count: hidden,
    groups: [{ type: 'resolves_to', direction: 'incoming', total, items }],
  }
}

const wrap = ({ children }: { children: ReactNode }) => (
  <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{children}</SWRConfig>
)

beforeEach(() => {
  api.get.mockReset()
})

describe('ClusterMembers', () => {
  it('names the first members with the rest counted, and asks only for this group', async () => {
    api.get.mockResolvedValue(
      response(
        names.map((n, i) => item(`a${i}`, n)),
        22
      )
    )
    const onNavigate = vi.fn()
    render(<ClusterMembers cluster={cluster} onNavigateToAsset={onNavigate} />, { wrapper: wrap })

    const list = await screen.findByRole('list', { name: 'Assets in this group' })
    expect(within(list).getAllByRole('button')).toHaveLength(CLUSTER_PREVIEW)
    for (const n of names) expect(within(list).getByText(n)).toBeInTheDocument()
    expect(screen.getByText('and 17 more')).toBeInTheDocument()

    const url = String(api.get.mock.calls[0][0])
    expect(url).toContain('/assets/ip-1/relationships/groups?')
    expect(url).toContain('type=resolves_to')
    expect(url).toContain('direction=incoming')
    expect(url).toContain(`limit=${CLUSTER_PREVIEW}`)

    await userEvent.click(within(list).getByRole('button', { name: /host-2\.example\.com/ }))
    expect(onNavigate).toHaveBeenCalledWith('a1', 'host-2.example.com')
  })

  it('starts after the members already drawn in the graph', async () => {
    api.get.mockResolvedValue(response([item('a9', 'host-9.example.com')], 60))
    render(<ClusterMembers cluster={{ ...cluster, remaining: 10, offset: 50 }} />, {
      wrapper: wrap,
    })
    await screen.findByText('host-9.example.com')
    expect(String(api.get.mock.calls[0][0])).toContain('offset=50')
    expect(screen.getByText('and 9 more')).toBeInTheDocument()
  })

  it('never shows a name from another group in the same response', async () => {
    const res = response([item('a0', names[0])], 22)
    res.groups.push({
      type: 'contains',
      direction: 'outgoing',
      total: 1,
      items: [item('x', 'other-group.example.com', 'contains', 'outgoing')],
    })
    // A stray row of another type inside the group is dropped too.
    res.groups[0].items.push(item('y', 'stray.example.com', 'contains', 'incoming'))
    api.get.mockResolvedValue(res)
    render(<ClusterMembers cluster={cluster} />, { wrapper: wrap })
    await screen.findByText(names[0])
    expect(screen.queryByText('other-group.example.com')).not.toBeInTheDocument()
    expect(screen.queryByText('stray.example.com')).not.toBeInTheDocument()
  })

  it('names nothing when the caller may see none of the members', async () => {
    api.get.mockResolvedValue(response([], 0, 22))
    render(<ClusterMembers cluster={cluster} />, { wrapper: wrap })
    expect(await screen.findByText('None of these assets is in your data scope')).toBeVisible()
    expect(screen.queryByRole('list')).not.toBeInTheDocument()
  })

  it('says the list failed instead of showing an empty card', async () => {
    api.get.mockRejectedValue(new Error('boom'))
    render(<ClusterMembers cluster={cluster} />, { wrapper: wrap })
    expect(await screen.findByText('Could not load the assets in this group')).toBeVisible()
  })
})

describe('clusterPreviewItems', () => {
  it('returns nothing without a response or a matching group', () => {
    expect(clusterPreviewItems(undefined, cluster)).toEqual({ items: [], total: 0 })
    expect(
      clusterPreviewItems(
        { total: 0, hidden_count: 0, groups: [] },
        { relType: 'contains', direction: 'outgoing' }
      )
    ).toEqual({ items: [], total: 0 })
  })
})

describe('cluster member strings', () => {
  it('exist in en and vi', () => {
    const en = enAssets as Record<string, string>
    const vi = viAssets as Record<string, string>
    for (const k of [
      'assets.graph.membersFailed',
      'assets.graph.membersNone',
      'assets.graph.membersLabel',
      'assets.graph.membersMore',
      'assets.graph.showAllHint',
    ]) {
      expect(en[k], k).toBeTruthy()
      expect(vi[k], k).toBeTruthy()
      expect(vi[k], k).not.toBe(en[k])
    }
  })
})
