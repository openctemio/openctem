/**
 * The run flow's pure parts: the layers of the run map's steps (a
 * layered layout: longest path from a root, then a barycenter ordering so
 * edges cross as little as possible), which way to draw them, why a
 * skipped step did not run, how long a step took, and what flowed along an
 * edge. The component draws; everything here is tested on its own.
 */
import type { RunMap, RunMapNode } from '@/lib/api/generated'
import { compactCount } from './run-map'
import { enTranslate, type Translate } from './translate'
import { formatScanDuration } from './format'

/**
 * The card width and the gaps the graph lays out with (px): between layers
 * left to right (room for an edge label), between layers top to bottom,
 * and between the steps of one layer.
 */
export const FLOW_CARD_WIDTH = 200
export const FLOW_GAP_X = 80
export const FLOW_GAP_Y = 48
export const FLOW_SIBLING_GAP = 12

/**
 * The steps as layers: layer i holds the steps whose longest chain of
 * dependencies from a root is i long. Unknown dependencies are ignored and
 * a step on a cycle (a saved workflow has none) falls back to layer 0, so
 * every step is drawn once. Within a layer, steps are ordered by the mean
 * position of their dependencies (two sweeps), ties in map order.
 */
export function flowLayers(nodes: RunMapNode[]): string[][] {
  const keys = nodes.map((n) => n.step_key ?? '')
  const known = new Set(keys)
  const deps = new Map<string, string[]>()
  for (const n of nodes) {
    deps.set(
      n.step_key ?? '',
      (n.depends_on ?? []).filter((d) => known.has(d) && d !== n.step_key)
    )
  }
  const level = new Map<string, number>()
  const visiting = new Set<string>()
  const depth = (k: string): number => {
    const cached = level.get(k)
    if (cached !== undefined) return cached
    if (visiting.has(k)) return 0
    visiting.add(k)
    let d = 0
    for (const p of deps.get(k) ?? []) d = Math.max(d, depth(p) + 1)
    visiting.delete(k)
    level.set(k, d)
    return d
  }
  const layers: string[][] = []
  for (const k of keys) {
    const d = depth(k)
    while (layers.length <= d) layers.push([])
    layers[d].push(k)
  }
  // Barycenter ordering: each layer sorted by the mean index of its
  // dependencies in the layers above; a step without one keeps its place.
  const index = new Map<string, number>()
  const reindex = (layer: string[]) => layer.forEach((k, i) => index.set(k, i))
  layers.forEach(reindex)
  for (let sweep = 0; sweep < 2; sweep++) {
    for (let i = 1; i < layers.length; i++) {
      const weight = new Map<string, number>()
      layers[i].forEach((k, pos) => {
        const ps = (deps.get(k) ?? []).map((p) => index.get(p) ?? 0)
        weight.set(k, ps.length ? ps.reduce((a, b) => a + b, 0) / ps.length : pos)
      })
      layers[i] = [...layers[i]].sort(
        (a, b) => (weight.get(a) ?? 0) - (weight.get(b) ?? 0) || keys.indexOf(a) - keys.indexOf(b)
      )
      reindex(layers[i])
    }
  }
  return layers
}

/** Whether some steps run side by side (a layer with more than one step). */
export function hasParallelBranches(layers: string[][]): boolean {
  return layers.some((l) => l.length > 1)
}

/**
 * The direction that fits the width: left to right when every layer fits
 * side by side, else top to bottom when the widest layer fits, else none
 * (the list is shown instead). A flow without parallel branches is a
 * list: a chain reads best as one column.
 */
export function flowDirection(layers: string[][], width: number): 'LR' | 'TB' | null {
  if (!hasParallelBranches(layers) || width <= 0) return null
  const span = (n: number, gap: number) => n * FLOW_CARD_WIDTH + Math.max(0, n - 1) * gap
  if (span(layers.length, FLOW_GAP_X) <= width) return 'LR'
  const widest = Math.max(...layers.map((l) => l.length))
  if (span(widest, FLOW_SIBLING_GAP) <= width) return 'TB'
  return null
}

const NOT_RUN = new Set(['failed', 'partial', 'skipped', 'canceled'])

/**
 * The step a skipped (or canceled) step did not run because of: the
 * nearest upstream step that failed, else the nearest that did not run.
 * Read from the map's own dependencies, so it holds for every run.
 */
export function blockingUpstream(
  node: RunMapNode,
  byKey: Map<string, RunMapNode>
): { node: RunMapNode; failed: boolean } | null {
  if (node.state !== 'skipped' && node.state !== 'canceled') return null
  const seen = new Set<string>([node.step_key ?? ''])
  let frontier = node.depends_on ?? []
  let fallback: RunMapNode | null = null
  while (frontier.length) {
    const next: string[] = []
    for (const k of frontier) {
      if (seen.has(k)) continue
      seen.add(k)
      const up = byKey.get(k)
      if (!up) continue
      if (up.state === 'failed' || up.state === 'partial') return { node: up, failed: true }
      if (NOT_RUN.has(up.state ?? '') && !fallback) fallback = up
      next.push(...(up.depends_on ?? []))
    }
    frontier = next
  }
  return fallback ? { node: fallback, failed: false } : null
}

/** "Skipped: HTTP probe failed", or null when no upstream step explains it. */
export function skippedReasonText(
  node: RunMapNode,
  byKey: Map<string, RunMapNode>,
  t: Translate = enTranslate
): string | null {
  const up = blockingUpstream(node, byKey)
  if (!up) return null
  const step = up.node.name || up.node.step_key || ''
  return up.failed
    ? t('scans.flow.skippedFailed', undefined, { step })
    : t('scans.flow.skippedNotRun', undefined, { step })
}

/** How long a step ran (ms): to its end, or to now while it runs. */
export function stepDurationMs(node: RunMapNode, now: number = Date.now()): number | null {
  if (!node.started_at) return null
  const start = Date.parse(node.started_at)
  const end = node.completed_at ? Date.parse(node.completed_at) : now
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) return null
  return end - start
}

/** "3m 12s", "<1s", or null when the step has not started. */
export function stepDurationLabel(node: RunMapNode, now: number = Date.now()): string | null {
  const ms = stepDurationMs(node, now)
  if (ms === null) return null
  return ms < 1000 ? '<1s' : formatScanDuration(ms)
}

/** A step's chunk progress, 0-100 (null without chunks). */
export function stepProgress(node: RunMapNode): number | null {
  const total = node.chunks?.total ?? 0
  if (total <= 0) return null
  const done = (node.chunks?.completed ?? 0) + (node.chunks?.failed ?? 0)
  return Math.min(100, Math.round((done / total) * 100))
}

/** What flowed along an edge ("66 outputs"), or null when nothing did. */
export function edgeHandOff(
  map: RunMap | undefined,
  from: string,
  to: string,
  t: Translate = enTranslate
): string | null {
  const e = (map?.edges ?? []).find((x) => x.from === from && x.to === to)
  const n = e?.count ?? 0
  return n > 0 ? t('scans.map.outputs', undefined, { count: compactCount(n) }) : null
}

/** The status family a map state is drawn in. */
export type FlowTone = 'pending' | 'waiting' | 'running' | 'done' | 'partial' | 'failed' | 'skipped'

export function flowTone(state?: string): FlowTone {
  switch (state) {
    case 'running':
      return 'running'
    case 'succeeded':
      return 'done'
    case 'partial':
      return 'partial'
    case 'failed':
      return 'failed'
    case 'skipped':
    case 'canceled':
      return 'skipped'
    case 'waiting':
      return 'waiting'
    default:
      return 'pending'
  }
}
