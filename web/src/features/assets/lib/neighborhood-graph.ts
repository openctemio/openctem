/**
 * The asset neighborhood graph (api docs/architecture/asset-relationships.md,
 * "Neighborhood"): GET /api/v1/assets/{id}/neighborhood answers the assets
 * around one asset, with large sibling groups as counted clusters and the
 * asset's discovery lineage. This module turns answers into one graph the
 * canvas draws: merging later answers (expand from a node, open a cluster),
 * drawing the lineage, and placing nodes in columns (sources left, targets
 * right) so the lineage reads from the root on the left to the asset.
 */
import type { RelatedAssetItem } from '../hooks/use-related-assets'
import type { AssetLineage } from './asset-lineage'

export type NeighborhoodDirection = 'outgoing' | 'incoming'

export interface NeighborhoodNodeDto {
  id: string
  name: string
  type: string
  sub_type?: string
  status?: string
  criticality?: string
  exposure?: string
  distance?: number
  expanded: boolean
  hidden_neighbors: number
}

export interface NeighborhoodEdgeDto {
  source: string
  target: string
  type: string
}

export interface NeighborhoodClusterDto {
  id: string
  anchor: string
  type: string
  direction: NeighborhoodDirection
  count: number
  by_type: Record<string, number>
}

export interface NeighborhoodResponse {
  asset_id: string
  depth: number
  direction: string
  max_nodes: number
  nodes: NeighborhoodNodeDto[]
  edges: NeighborhoodEdgeDto[]
  clusters: NeighborhoodClusterDto[]
  lineage: AssetLineage
  truncated: boolean
  hidden_count: number
}

export interface GraphAssetNode {
  kind: 'asset'
  id: string
  name: string
  type: string
  criticality?: string
  expanded: boolean
  hiddenNeighbors: number
  /** The asset the page is about. */
  self: boolean
  /** On the asset's discovery lineage. */
  lineage: boolean
  /** The top of the lineage (where the asset comes from). */
  root: boolean
}

export interface GraphClusterNode {
  kind: 'cluster'
  id: string
  anchor: string
  relType: string
  direction: NeighborhoodDirection
  /** Assets not drawn yet. */
  remaining: number
  byType: Record<string, number>
  /** Rows already read from the relationship groups endpoint. */
  offset: number
}

/** A lineage hop outside the caller's data scope: no identity at all. */
export interface GraphHiddenNode {
  kind: 'hidden'
  id: string
  root: boolean
}

export type GraphNode = GraphAssetNode | GraphClusterNode | GraphHiddenNode

export interface GraphEdge {
  id: string
  source: string
  target: string
  /** A relationship type, or 'parent' for an asset's own parent. */
  type: string
  lineage: boolean
}

export interface NeighborhoodGraph {
  rootId: string
  /** Insertion order is the reading order inside a column. */
  nodes: Map<string, GraphNode>
  edges: Map<string, GraphEdge>
  truncated: boolean
  lineageTruncated: boolean
}

const edgeKey = (source: string, target: string, type: string) => `${source}>${target}:${type}`

/** The id of a hidden lineage hop. */
export const hiddenLineageId = (depth: number) => `hidden:lineage:${depth}`

function addEdge(
  g: NeighborhoodGraph,
  source: string,
  target: string,
  type: string,
  lineage: boolean
) {
  const id = edgeKey(source, target, type)
  const cur = g.edges.get(id)
  if (cur) {
    if (lineage) cur.lineage = true
    return
  }
  g.edges.set(id, { id, source, target, type, lineage })
}

function upsertAsset(g: NeighborhoodGraph, n: NeighborhoodNodeDto) {
  const cur = g.nodes.get(n.id)
  if (cur?.kind === 'asset') {
    cur.name = n.name || cur.name
    cur.type = n.type || cur.type
    cur.criticality = n.criticality || cur.criticality
    if (n.expanded) {
      cur.expanded = true
      cur.hiddenNeighbors = n.hidden_neighbors
    }
    return
  }
  g.nodes.set(n.id, {
    kind: 'asset',
    id: n.id,
    name: n.name,
    type: n.type,
    criticality: n.criticality,
    expanded: n.expanded,
    hiddenNeighbors: n.hidden_neighbors,
    self: false,
    lineage: false,
    root: false,
  })
}

function addClusters(g: NeighborhoodGraph, clusters: NeighborhoodClusterDto[]) {
  for (const c of clusters) {
    if (g.nodes.has(c.id) || c.count <= 0) continue
    g.nodes.set(c.id, {
      kind: 'cluster',
      id: c.id,
      anchor: c.anchor,
      relType: c.type,
      direction: c.direction,
      remaining: c.count,
      byType: { ...c.by_type },
      offset: 0,
    })
    if (c.direction === 'outgoing') addEdge(g, c.anchor, c.id, c.type, false)
    else addEdge(g, c.id, c.anchor, c.type, false)
  }
}

/** The graph of a first answer: the asset, its neighborhood and its lineage. */
export function buildNeighborhoodGraph(res: NeighborhoodResponse): NeighborhoodGraph {
  const g: NeighborhoodGraph = {
    rootId: res.asset_id,
    nodes: new Map(),
    edges: new Map(),
    truncated: res.truncated,
    lineageTruncated: res.lineage?.truncated ?? false,
  }
  for (const n of res.nodes) upsertAsset(g, n)
  const self = g.nodes.get(res.asset_id)
  if (self?.kind === 'asset') self.self = true
  for (const e of res.edges) addEdge(g, e.source, e.target, e.type, false)
  addClusters(g, res.clusters)

  // Lineage: depth d+1 leads to depth d (parent -> child), always drawn.
  const chain = [...(res.lineage?.nodes ?? [])].sort((a, b) => a.depth - b.depth)
  const idOf = (n: (typeof chain)[number]) =>
    n.depth === 0 ? res.asset_id : n.hidden ? hiddenLineageId(n.depth) : (n.id as string)
  const top = chain.length > 1 ? chain[chain.length - 1] : undefined
  for (const n of chain) {
    if (n.depth === 0) continue
    const id = idOf(n)
    const isRoot = n === top && !res.lineage.truncated
    if (n.hidden) {
      g.nodes.set(id, { kind: 'hidden', id, root: isRoot })
    } else {
      const cur = g.nodes.get(id)
      if (!cur) {
        upsertAsset(g, {
          id,
          name: n.name ?? '',
          type: n.type ?? '',
          expanded: false,
          hidden_neighbors: 0,
        })
      }
      const node = g.nodes.get(id)
      if (node?.kind === 'asset') {
        node.lineage = true
        node.root = isRoot
      }
    }
  }
  for (const n of chain) {
    const child = chain.find((c) => c.depth === n.depth - 1)
    if (!child || !n.via) continue
    addEdge(g, idOf(n), idOf(child), n.via, true)
  }
  return g
}

/** Copies a graph so React sees a new value. */
function clone(g: NeighborhoodGraph): NeighborhoodGraph {
  const nodes = new Map<string, GraphNode>()
  for (const [k, v] of g.nodes) nodes.set(k, { ...v })
  const edges = new Map<string, GraphEdge>()
  for (const [k, v] of g.edges) edges.set(k, { ...v })
  return { ...g, nodes, edges }
}

/** Merges the depth-1 neighborhood of one node (expand from it). */
export function mergeExpansion(g: NeighborhoodGraph, res: NeighborhoodResponse): NeighborhoodGraph {
  const out = clone(g)
  for (const n of res.nodes) upsertAsset(out, n)
  const anchor = out.nodes.get(res.asset_id)
  if (anchor?.kind === 'asset') anchor.expanded = true
  for (const e of res.edges) addEdge(out, e.source, e.target, e.type, false)
  // A cluster for a group the graph already shows in part is left out: its
  // members are reached through the existing cluster.
  addClusters(
    out,
    res.clusters.filter(
      (c) =>
        ![...out.nodes.values()].some(
          (n) =>
            n.kind === 'cluster' &&
            n.anchor === c.anchor &&
            n.relType === c.type &&
            n.direction === c.direction
        )
    )
  )
  out.truncated = out.truncated || res.truncated
  return out
}

/**
 * Draws one page of a cluster's members, read from the relationship groups
 * endpoint (same anchor, type and direction). The cluster stays with what is
 * left, or goes when nothing is.
 */
export function mergeClusterPage(
  g: NeighborhoodGraph,
  clusterId: string,
  items: RelatedAssetItem[],
  groupTotal: number
): NeighborhoodGraph {
  const out = clone(g)
  const c = out.nodes.get(clusterId)
  if (c?.kind !== 'cluster') return g
  let added = 0
  for (const it of items) {
    if (it.type !== c.relType || it.direction !== c.direction) continue
    if (!out.nodes.has(it.asset.id)) added++
    upsertAsset(out, {
      id: it.asset.id,
      name: it.asset.name,
      type: it.asset.type,
      criticality: it.asset.criticality,
      expanded: false,
      hidden_neighbors: 0,
    })
    if (c.direction === 'outgoing') addEdge(out, c.anchor, it.asset.id, c.relType, false)
    else addEdge(out, it.asset.id, c.anchor, c.relType, false)
  }
  c.offset += items.length
  c.remaining = Math.max(0, Math.min(c.remaining - added, groupTotal - c.offset))
  if (c.remaining <= 0 || items.length === 0) {
    out.nodes.delete(clusterId)
    for (const [k, e] of out.edges)
      if (e.source === clusterId || e.target === clusterId) out.edges.delete(k)
  }
  return out
}

export interface PlacedNode {
  id: string
  x: number
  y: number
  column: number
}

/**
 * Layers from the asset outwards: a node one edge downstream of a node in
 * layer c goes to c+1, one edge upstream to c-1 (breadth first, the first
 * placement wins, so cycles cannot loop). Lineage ancestors land above the
 * asset (or left of it), what it exposes below (or right). Each layer is
 * centred on the asset. Top to bottom by default: the graph lives in a
 * narrow sheet, and a lineage of five ancestors stays readable.
 */
export function layoutNeighborhood(
  g: NeighborhoodGraph,
  opts: {
    layerGap?: number
    nodeGap?: number
    rowGap?: number
    perRow?: number
    direction?: 'TB' | 'LR'
  } = {}
): PlacedNode[] {
  const tb = (opts.direction ?? 'TB') === 'TB'
  const layerGap = opts.layerGap ?? (tb ? 130 : 250)
  const nodeGap = opts.nodeGap ?? (tb ? 200 : 104)
  const rowGap = opts.rowGap ?? 84
  const adj = new Map<string, { to: string; delta: number }[]>()
  const push = (from: string, to: string, delta: number) => {
    const list = adj.get(from)
    if (list) list.push({ to, delta })
    else adj.set(from, [{ to, delta }])
  }
  for (const e of g.edges.values()) {
    if (!g.nodes.has(e.source) || !g.nodes.has(e.target)) continue
    push(e.source, e.target, 1)
    push(e.target, e.source, -1)
  }
  const column = new Map<string, number>([[g.rootId, 0]])
  const queue = [g.rootId]
  while (queue.length) {
    const id = queue.shift() as string
    const c = column.get(id) as number
    for (const { to, delta } of adj.get(id) ?? []) {
      if (column.has(to)) continue
      column.set(to, c + delta)
      queue.push(to)
    }
  }
  const byColumn = new Map<number, string[]>()
  for (const id of g.nodes.keys()) {
    const c = column.get(id) ?? 0
    const list = byColumn.get(c)
    if (list) list.push(id)
    else byColumn.set(c, [id])
  }
  // A wide layer wraps onto several rows (perRow nodes each), so an
  // expanded cluster of fifty addresses stays readable instead of shrinking
  // the whole graph; the layers below move down to make room.
  const perRow = opts.perRow ?? 5
  const rowsOf = (n: number) => (tb ? Math.max(1, Math.ceil(n / perRow)) : 1)
  const layers = [...byColumn.keys()].sort((a, b) => a - b)
  const offset = new Map<number, number>()
  // The asset's layer stays at 0; layers above stack upwards.
  let down = 0
  for (const c of layers.filter((c) => c >= 0)) {
    offset.set(c, down)
    down += layerGap + (rowsOf(byColumn.get(c)!.length) - 1) * rowGap
  }
  let up = 0
  for (const c of layers.filter((c) => c < 0).reverse()) {
    up -= layerGap + (rowsOf(byColumn.get(c)!.length) - 1) * rowGap
    offset.set(c, up)
  }
  const out: PlacedNode[] = []
  for (const [c, ids] of byColumn) {
    // The lineage first (it is the spine), then the rest in reading order.
    const ordered = [...ids].sort((a, b) => spineRank(g, a) - spineRank(g, b))
    const width = tb ? Math.min(perRow, ordered.length) : ordered.length
    ordered.forEach((id, i) => {
      const slot = tb ? i % perRow : i
      const row = tb ? Math.floor(i / perRow) : 0
      const inRow = tb ? Math.min(perRow, ordered.length - row * perRow) : width
      const along = (slot - (inRow - 1) / 2) * nodeGap
      out.push({
        id,
        column: c,
        x: tb ? along : c * layerGap,
        y: tb ? (offset.get(c) ?? 0) + row * rowGap : along,
      })
    })
  }
  return out
}

function spineRank(g: NeighborhoodGraph, id: string): number {
  const n = g.nodes.get(id)
  if (!n) return 3
  if (n.kind === 'hidden' || (n.kind === 'asset' && (n.self || n.lineage))) return 0
  return n.kind === 'cluster' ? 2 : 1
}

/** Asset types present in the graph, for the legend (first seen first). */
export function graphTypes(g: NeighborhoodGraph): string[] {
  const seen = new Set<string>()
  for (const n of g.nodes.values()) {
    if (n.kind === 'asset' && n.type) seen.add(n.type)
    if (n.kind === 'cluster') for (const t of Object.keys(n.byType)) seen.add(t)
  }
  return [...seen]
}

/** The single asset type of a cluster, or undefined when it mixes types. */
export function clusterType(c: GraphClusterNode): string | undefined {
  const types = Object.keys(c.byType).filter((t) => c.byType[t] > 0)
  return types.length === 1 ? types[0] : undefined
}

/**
 * The colour of an asset type's dot, from the categorical chart palette
 * (light and dark tokens). The common attack-surface types have fixed
 * colours so a type looks the same on every asset; the rest share by hash.
 */
const TYPE_DOTS: Record<string, string> = {
  domain: 'bg-[var(--viz-cat-1)]',
  ip_address: 'bg-[var(--viz-cat-2)]',
  certificate: 'bg-[var(--viz-cat-3)]',
  service: 'bg-[var(--viz-cat-4)]',
  subdomain: 'bg-[var(--viz-cat-5)]',
  host: 'bg-[var(--viz-cat-6)]',
  website: 'bg-[var(--viz-cat-7)]',
}
const DOT_POOL = [
  'bg-[var(--viz-cat-1)]',
  'bg-[var(--viz-cat-2)]',
  'bg-[var(--viz-cat-3)]',
  'bg-[var(--viz-cat-4)]',
  'bg-[var(--viz-cat-5)]',
  'bg-[var(--viz-cat-6)]',
  'bg-[var(--viz-cat-7)]',
]

export function typeDotClass(type: string | undefined): string {
  if (!type) return 'bg-muted-foreground'
  const fixed = TYPE_DOTS[type]
  if (fixed) return fixed
  let h = 0
  for (const ch of type) h = (h * 31 + ch.charCodeAt(0)) >>> 0
  return DOT_POOL[h % DOT_POOL.length]
}
