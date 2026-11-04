import { describe, expect, it } from 'vitest'
import type { RelatedAssetItem } from '../../hooks/use-related-assets'
import {
  buildNeighborhoodGraph,
  hiddenLineageId,
  layoutNeighborhood,
  mergeClusterPage,
  mergeExpansion,
  typeDotClass,
  type NeighborhoodResponse,
} from '../neighborhood-graph'

// The owner's case: an address, the mail name that resolves to it (and to ten
// more addresses), the root domain that contains the name, a service on the
// address and its certificate.
function ipAnswer(): NeighborhoodResponse {
  return {
    asset_id: 'ip0',
    depth: 2,
    direction: 'both',
    max_nodes: 150,
    nodes: [
      {
        id: 'ip0',
        name: '52.98.54.130',
        type: 'ip_address',
        distance: 0,
        expanded: true,
        hidden_neighbors: 0,
      },
      {
        id: 'mail',
        name: 'mail.example.com',
        type: 'subdomain',
        distance: 1,
        expanded: true,
        hidden_neighbors: 0,
      },
      {
        id: 'dom',
        name: 'example.com',
        type: 'domain',
        distance: 2,
        expanded: false,
        hidden_neighbors: 0,
      },
      {
        id: 'svc',
        name: '52.98.54.130:443',
        type: 'service',
        distance: 1,
        expanded: true,
        hidden_neighbors: 2,
      },
      {
        id: 'cert',
        name: 'sha256',
        type: 'certificate',
        distance: 2,
        expanded: false,
        hidden_neighbors: 0,
      },
    ],
    edges: [
      { source: 'mail', target: 'ip0', type: 'resolves_to' },
      { source: 'ip0', target: 'svc', type: 'exposes' },
      { source: 'dom', target: 'mail', type: 'contains' },
      { source: 'svc', target: 'cert', type: 'serves_certificate' },
    ],
    clusters: [
      {
        id: 'cluster:mail:resolves_to:outgoing',
        anchor: 'mail',
        type: 'resolves_to',
        direction: 'outgoing',
        count: 10,
        by_type: { ip_address: 10 },
      },
    ],
    lineage: {
      max_depth: 5,
      truncated: false,
      nodes: [
        { depth: 0, hidden: false, id: 'ip0', name: '52.98.54.130', type: 'ip_address' },
        {
          depth: 1,
          hidden: false,
          via: 'resolves_to',
          id: 'mail',
          name: 'mail.example.com',
          type: 'subdomain',
        },
        {
          depth: 2,
          hidden: false,
          via: 'contains',
          id: 'dom',
          name: 'example.com',
          type: 'domain',
        },
      ],
    },
    truncated: false,
    hidden_count: 2,
  }
}

describe('buildNeighborhoodGraph', () => {
  it('draws the lineage up to the root and marks it', () => {
    const g = buildNeighborhoodGraph(ipAnswer())
    const dom = g.nodes.get('dom')
    expect(dom).toMatchObject({ kind: 'asset', lineage: true, root: true })
    expect(g.nodes.get('ip0')).toMatchObject({ self: true })
    expect(g.edges.get('dom>mail:contains')?.lineage).toBe(true)
    expect(g.edges.get('mail>ip0:resolves_to')?.lineage).toBe(true)
    expect(g.edges.get('ip0>svc:exposes')?.lineage).toBe(false)
  })

  it('draws a sibling group as one cluster node', () => {
    const g = buildNeighborhoodGraph(ipAnswer())
    const c = g.nodes.get('cluster:mail:resolves_to:outgoing')
    expect(c).toMatchObject({ kind: 'cluster', remaining: 10 })
    expect(g.edges.has('mail>cluster:mail:resolves_to:outgoing:resolves_to')).toBe(true)
  })

  it('draws a hidden lineage hop with no identity', () => {
    const res = ipAnswer()
    res.lineage.nodes[1] = { depth: 1, hidden: true, via: 'resolves_to' }
    res.nodes = res.nodes.filter((n) => n.id !== 'mail')
    const g = buildNeighborhoodGraph(res)
    expect(g.nodes.get(hiddenLineageId(1))).toEqual({
      kind: 'hidden',
      id: hiddenLineageId(1),
      root: false,
    })
    expect(g.edges.has(`dom>${hiddenLineageId(1)}:contains`)).toBe(true)
    expect(g.edges.has(`${hiddenLineageId(1)}>ip0:resolves_to`)).toBe(true)
  })

  it('places the lineage above the asset and what it exposes below', () => {
    const g = buildNeighborhoodGraph(ipAnswer())
    const col = Object.fromEntries(layoutNeighborhood(g).map((p) => [p.id, p.column]))
    expect(col).toMatchObject({ ip0: 0, mail: -1, dom: -2, svc: 1, cert: 2 })
    const at = Object.fromEntries(layoutNeighborhood(g).map((p) => [p.id, p]))
    expect(at.dom.y).toBeLessThan(at.mail.y)
    expect(at.mail.y).toBeLessThan(at.ip0.y)
  })

  it('survives a cycle in the layout', () => {
    const res = ipAnswer()
    res.edges.push({ source: 'cert', target: 'dom', type: 'contains' })
    const placed = layoutNeighborhood(buildNeighborhoodGraph(res))
    expect(new Set(placed.map((p) => p.id)).size).toBe(placed.length)
  })
})

describe('merging', () => {
  it('merges an expansion without duplicating nodes or clusters', () => {
    const g = buildNeighborhoodGraph(ipAnswer())
    const next = mergeExpansion(g, {
      ...ipAnswer(),
      asset_id: 'dom',
      nodes: [
        {
          id: 'dom',
          name: 'example.com',
          type: 'domain',
          distance: 0,
          expanded: true,
          hidden_neighbors: 1,
        },
        {
          id: 'www',
          name: 'www.example.com',
          type: 'subdomain',
          distance: 1,
          expanded: false,
          hidden_neighbors: 0,
        },
      ],
      edges: [{ source: 'dom', target: 'www', type: 'contains' }],
    })
    expect(next).not.toBe(g)
    expect(next.nodes.get('dom')).toMatchObject({ expanded: true, hiddenNeighbors: 1, root: true })
    expect(next.nodes.has('www')).toBe(true)
    expect([...next.nodes.values()].filter((n) => n.kind === 'cluster')).toHaveLength(1)
    expect(g.nodes.has('www')).toBe(false)
  })

  it('draws a cluster page and drops the cluster when it is empty', () => {
    const g = buildNeighborhoodGraph(ipAnswer())
    const id = 'cluster:mail:resolves_to:outgoing'
    const item = (n: number): RelatedAssetItem => ({
      relationship_id: `r${n}`,
      type: 'resolves_to',
      direction: 'outgoing',
      asset: { id: `ip${n}`, name: `10.0.0.${n}`, type: 'ip_address' },
      discovery_method: 'automatic',
      confidence: 'high',
      is_control_plane: false,
      created_at: '2026-11-04T00:00:00Z',
    })
    // The group total counts the address already drawn (ip0) too.
    const first = mergeClusterPage(g, id, [item(0), ...[1, 2, 3, 4].map(item)], 11)
    expect(first.nodes.get(id)).toMatchObject({ kind: 'cluster', remaining: 6, offset: 5 })
    expect(first.edges.has('mail>ip3:resolves_to')).toBe(true)
    const rest = mergeClusterPage(first, id, [5, 6, 7, 8, 9, 10].map(item), 11)
    expect(rest.nodes.has(id)).toBe(false)
    expect([...rest.edges.values()].some((e) => e.target === id)).toBe(false)
  })
})

describe('typeDotClass', () => {
  it('keeps one colour per type', () => {
    expect(typeDotClass('domain')).toBe(typeDotClass('domain'))
    expect(typeDotClass('domain')).not.toBe(typeDotClass('ip_address'))
    expect(typeDotClass('kubernetes_namespace')).toMatch(/^bg-\[var\(--viz-cat-\d\)\]$/)
  })
})

describe('layoutNeighborhood wrapping', () => {
  it('wraps a wide layer onto rows and keeps the lineage above', () => {
    const res = ipAnswer()
    res.clusters = []
    for (let i = 1; i <= 12; i++) {
      res.nodes.push({
        id: `ipx${i}`,
        name: `10.0.0.${i}`,
        type: 'ip_address',
        distance: 2,
        expanded: false,
        hidden_neighbors: 0,
      })
      res.edges.push({ source: 'mail', target: `ipx${i}`, type: 'resolves_to' })
    }
    const at = Object.fromEntries(
      layoutNeighborhood(buildNeighborhoodGraph(res)).map((p) => [p.id, p])
    )
    const row = (id: string) => at[id].y
    // ip0 and twelve more addresses share layer 0: three rows of five at most.
    const ys = new Set([...Array(12)].map((_, i) => row(`ipx${i + 1}`)).concat(row('ip0')))
    expect(ys.size).toBe(3)
    expect(
      Math.max(...[...Array(12)].map((_, i) => Math.abs(at[`ipx${i + 1}`].x)))
    ).toBeLessThanOrEqual(400)
    expect(at.mail.y).toBeLessThan(at.ip0.y)
    // What the asset exposes sits below the last row of its layer.
    expect(at.svc.y).toBeGreaterThan(Math.max(...ys))
  })
})
