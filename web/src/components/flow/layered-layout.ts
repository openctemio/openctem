import type { FlowEdgeLike } from './connection-rules'

/**
 * A layered layout for a small DAG (left to right, or top to bottom): each node's column is the
 * length of its longest path from a root, and nodes stack in a column in
 * input order. Nodes on a cycle (which a saved workflow never has) fall
 * back to column 0. Positions are cosmetic.
 */
export function layeredLayout(
  ids: string[],
  edges: FlowEdgeLike[],
  opts: { columnWidth?: number; rowHeight?: number; direction?: 'LR' | 'TB' } = {}
): Record<string, { x: number; y: number }> {
  const colW = opts.columnWidth ?? 300
  const rowH = opts.rowHeight ?? 140
  const known = new Set(ids)
  const preds = new Map<string, string[]>()
  for (const e of edges) {
    if (!known.has(e.source) || !known.has(e.target)) continue
    preds.set(e.target, [...(preds.get(e.target) ?? []), e.source])
  }
  const level = new Map<string, number>()
  const visiting = new Set<string>()
  const depth = (id: string): number => {
    const cached = level.get(id)
    if (cached !== undefined) return cached
    if (visiting.has(id)) return 0
    visiting.add(id)
    const d = Math.max(-1, ...(preds.get(id) ?? []).map(depth)) + 1
    visiting.delete(id)
    level.set(id, d)
    return d
  }
  const rows = new Map<number, number>()
  const out: Record<string, { x: number; y: number }> = {}
  for (const id of ids) {
    const col = depth(id)
    const row = rows.get(col) ?? 0
    rows.set(col, row + 1)
    out[id] =
      opts.direction === 'TB' ? { x: row * colW, y: col * rowH } : { x: col * colW, y: row * rowH }
  }
  return out
}
