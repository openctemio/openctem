import type { AttackPathDetail, PathNode } from '../hooks/use-attack-path-detail'

/**
 * Pure model of the attack-path view: which routes are shown, where each node
 * sits, which nodes and edges light up for a hovered node or a selected path,
 * the choke-point rows and the score breakdown. No React, so it is tested on
 * its own (attack-path-model.test.ts).
 */

/** The virtual source of every route: the internet. */
export const INTERNET = 'internet'

export type PathMode = 'shortest' | 'all'

/** Indexes of the routes shown: the first (shortest, most likely) or every one. */
export function shownPaths(detail: AttackPathDetail, mode: PathMode): number[] {
  if (detail.paths.length === 0) return []
  return mode === 'shortest' ? [0] : detail.paths.map((_, i) => i)
}

export interface LayoutNode {
  key: string
  column: number
  x: number
  y: number
}

export interface LayoutEdge {
  id: string
  /** INTERNET for the step onto an entry point. */
  from: string
  to: string
  paths: number[]
}

export interface PathLayout {
  nodes: LayoutNode[]
  edges: LayoutEdge[]
  /** Routes through each node key (shown routes only). */
  pathsByNode: Map<string, number[]>
}

const COLUMN_W = 340
const ROW_H = 140
/** The internet label sits left of the entry column, leaving room for the first edge label. */
const INTERNET_X = -220

/**
 * Lays the shown routes out left to right: the internet in column 0, each node
 * in the column of its longest distance from the internet, the nodes of a
 * column centred on the middle row so the main route runs straight.
 */
export function layoutPaths(detail: AttackPathDetail, shown: number[]): PathLayout {
  const shownSet = new Set(shown)
  const pathsByNode = new Map<string, number[]>()
  const order: string[] = []
  for (const i of shown) {
    for (const k of detail.paths[i]?.nodes ?? []) {
      if (!pathsByNode.has(k)) {
        pathsByNode.set(k, [])
        order.push(k)
      }
      pathsByNode.get(k)!.push(i)
    }
  }
  const edges: LayoutEdge[] = detail.edges
    .map((e) => ({
      id: `${e.from || INTERNET}->${e.to}`,
      from: e.from || INTERNET,
      to: e.to,
      paths: e.paths.filter((p) => shownSet.has(p)),
    }))
    .filter((e) => e.paths.length > 0)

  // Column = longest distance from the internet over the shown edges.
  const preds = new Map<string, string[]>()
  for (const e of edges) preds.set(e.to, [...(preds.get(e.to) ?? []), e.from])
  const col = new Map<string, number>([[INTERNET, 0]])
  const visiting = new Set<string>()
  const depth = (k: string): number => {
    const c = col.get(k)
    if (c !== undefined) return c
    if (visiting.has(k)) return 1
    visiting.add(k)
    const d = Math.max(0, ...(preds.get(k) ?? [INTERNET]).map(depth)) + 1
    visiting.delete(k)
    col.set(k, d)
    return d
  }
  // The target goes in the last column, so every route ends in one place.
  let last = 0
  for (const k of order) if (k !== detail.target) last = Math.max(last, depth(k))
  if (pathsByNode.has(detail.target)) col.set(detail.target, Math.max(last + 1, 1))

  const columns = new Map<number, string[]>()
  for (const k of order) {
    const c = col.get(k) ?? depth(k)
    columns.set(c, [...(columns.get(c) ?? []), k])
  }
  const nodes: LayoutNode[] = []
  for (const [c, keys] of columns) {
    keys.forEach((key, row) => {
      nodes.push({
        key,
        column: c,
        x: (c - 1) * COLUMN_W,
        y: (row - (keys.length - 1) / 2) * ROW_H,
      })
    })
  }
  if (nodes.length > 0) nodes.push({ key: INTERNET, column: 0, x: INTERNET_X, y: 0 })
  return { nodes, edges, pathsByNode }
}

export type Focus = { kind: 'node'; key: string } | { kind: 'path'; index: number } | null

export interface FocusSets {
  nodes: Set<string>
  edges: Set<string>
}

/**
 * What lights up: a hovered or focused node lights every shown route through
 * it; a path lights that route. Null when nothing is in focus (no dimming).
 */
export function focusSets(
  layout: PathLayout,
  detail: AttackPathDetail,
  focus: Focus
): FocusSets | null {
  if (!focus) return null
  let paths: number[]
  if (focus.kind === 'path') paths = [focus.index]
  else if (focus.key === INTERNET) paths = [...new Set([...layout.pathsByNode.values()].flat())]
  else paths = layout.pathsByNode.get(focus.key) ?? []
  const nodes = new Set<string>()
  const edges = new Set<string>()
  if (focus.kind === 'node') nodes.add(focus.key)
  for (const p of paths) {
    nodes.add(INTERNET)
    for (const k of detail.paths[p]?.nodes ?? []) nodes.add(k)
  }
  for (const e of layout.edges) if (e.paths.some((p) => paths.includes(p))) edges.add(e.id)
  return { nodes, edges }
}

export function nodeByKey(detail: AttackPathDetail): Map<string, PathNode> {
  return new Map(detail.nodes.map((n) => [n.key, n]))
}

/** The text of a step: the lead finding's CVE, else its title; '' when none. */
export function stepText(node: PathNode | undefined): string {
  if (!node?.finding) return ''
  return node.finding.cveId || node.finding.title
}

export interface ChokeRow {
  key: string
  node: PathNode
  breaks: number
  /** The routes shown in total ("cut 4 of 4 routes"). */
  of: number
}

export function chokeRows(detail: AttackPathDetail): ChokeRow[] {
  const byKey = nodeByKey(detail)
  return detail.chokePoints
    .map((c) => ({
      key: c.node,
      node: byKey.get(c.node)!,
      breaks: c.breaks,
      of: detail.paths.length,
    }))
    .filter((r) => r.node && !r.node.hidden)
}

export interface ScoreRow {
  key: string
  node: PathNode
  /** Weight of the step; null for a hidden step. */
  weight: number | null
}

export interface PathScore {
  rows: ScoreRow[]
  likelihood: number | null
}

/** The breakdown of one route: each step's weight, and their product. */
export function pathScore(detail: AttackPathDetail, index: number): PathScore | null {
  const p = detail.paths[index]
  if (!p) return null
  const byKey = nodeByKey(detail)
  return {
    rows: p.nodes.map((k) => ({
      key: k,
      node: byKey.get(k)!,
      weight: byKey.get(k)?.weight ?? null,
    })),
    likelihood: p.likelihood,
  }
}

/** Two decimals, the way weights are written everywhere on the page. */
export function formatWeight(w: number | null | undefined): string {
  return typeof w === 'number' && Number.isFinite(w) ? w.toFixed(2) : ''
}

/** The findings list of an asset, every open finding including informational ones. */
export function assetFindingsHref(assetId: string): string {
  return `/findings?asset_id=${encodeURIComponent(assetId)}&informational=true`
}

/** The page's own URL for a target, view and path mode. */
export function attackPathHref(target: string, extra: Record<string, string> = {}): string {
  const q = new URLSearchParams({ target, ...extra })
  return `/attack-paths?${q.toString()}`
}
