/**
 * Discovery lineage (api docs/architecture/easm.md, Discovery lineage): how an
 * asset was found, read from GET /api/v1/assets/{id}/lineage. The API returns
 * the asset first (depth 0) and its ancestors upwards; the page shows the
 * chain root first, so the reader follows discovery downwards to the asset.
 */
import type { TFn } from './default-t'
import { relationVerbFallback, relationVerbKey } from './relationship-verbs'

export interface AssetLineageNode {
  depth: number
  /** Outside the caller's data scope: no id, name, type or discovery fields. */
  hidden: boolean
  /** How this node leads to the node one depth below it ('' for the asset). */
  via?: string
  id?: string
  name?: string
  type?: string
  discovery_source?: string
  discovery_tool?: string
  discovered_at?: string
  first_seen?: string
}

export interface AssetLineage {
  nodes: AssetLineageNode[]
  max_depth: number
  /** The chain goes on above the first node shown. */
  truncated: boolean
}

/** One row of the chain as the page shows it, root first. */
export interface LineageStep {
  node: AssetLineageNode
  /** The asset the page is about (always the last step). */
  isSelf: boolean
  /** How the previous step leads to this one (empty on the first step). */
  edge?: string
}

/** Root first; each step carries the edge from the step above it. */
export function lineageSteps(lineage: AssetLineage | undefined): LineageStep[] {
  if (!lineage?.nodes?.length) return []
  const byDepth = [...lineage.nodes].sort((a, b) => b.depth - a.depth)
  return byDepth.map((node, i) => ({
    node,
    isSelf: node.depth === 0,
    edge: i === 0 ? undefined : byDepth[i - 1].via || undefined,
  }))
}

/** The asset's own node (depth 0). */
export function lineageSelf(lineage: AssetLineage | undefined): AssetLineageNode | undefined {
  return lineage?.nodes?.find((n) => n.depth === 0)
}

/** True when the asset has no known parent: it is a root itself. */
export function isLineageRoot(lineage: AssetLineage | undefined): boolean {
  return !!lineage && lineage.nodes.length <= 1 && !lineage.truncated
}

const SOURCE_FALLBACK: Record<string, string> = {
  dns: 'DNS',
  cert_transparency: 'Certificate logs',
  bruteforce: 'DNS brute force',
  passive: 'Passive sources',
  manual: 'Added by a person',
  api_discovery: 'API discovery',
  web_crawl: 'Web crawl',
  sensor: 'Sensor',
}

/** A discovery source in words; an unknown value reads humanised. */
export function discoverySourceLabel(t: TFn, source: string): string {
  const fallback = SOURCE_FALLBACK[source]
  if (fallback) return t(`assets.lineage.source.${source}`, fallback)
  const words = source.replace(/[-_]+/g, ' ').trim()
  return words.charAt(0).toUpperCase() + words.slice(1)
}

/** The edge between two steps, read downwards ("Contains", "Exposes"). */
export function lineageEdgeLabel(t: TFn, via: string): string {
  if (via === 'parent') return t('assets.lineage.via.parent', 'Parent of')
  return t(relationVerbKey(via, 'outgoing'), relationVerbFallback(via, 'outgoing'))
}
