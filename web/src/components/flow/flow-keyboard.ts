/**
 * Keyboard model of a flow canvas (research/229 §4.2): one node is in the tab
 * order at a time; the arrow keys follow the graph instead of the screen.
 *
 * - ArrowRight: the next node along an outgoing edge (the one nearest in height);
 * - ArrowLeft: the previous node along an incoming edge;
 * - ArrowDown / ArrowUp: the next node below or above in the same column;
 * - Home / End: the first or last node in reading order.
 *
 * Returns null when there is nowhere to go, so the focus stays put.
 */

export interface FlowKeyNode {
  id: string
  x: number
  y: number
}

export interface FlowKeyEdge {
  source: string
  target: string
}

export type FlowKey = 'ArrowRight' | 'ArrowLeft' | 'ArrowDown' | 'ArrowUp' | 'Home' | 'End'

export const FLOW_KEYS: ReadonlySet<string> = new Set<FlowKey>([
  'ArrowRight',
  'ArrowLeft',
  'ArrowDown',
  'ArrowUp',
  'Home',
  'End',
])

const readingOrder = (a: FlowKeyNode, b: FlowKeyNode) => a.x - b.x || a.y - b.y

export function flowNeighbour(
  current: string | null,
  key: string,
  nodes: FlowKeyNode[],
  edges: FlowKeyEdge[]
): string | null {
  if (nodes.length === 0) return null
  const sorted = [...nodes].sort(readingOrder)
  if (key === 'Home') return sorted[0].id
  if (key === 'End') return sorted[sorted.length - 1].id
  const here = nodes.find((n) => n.id === current)
  if (!here) return FLOW_KEYS.has(key) ? sorted[0].id : null

  const byId = new Map(nodes.map((n) => [n.id, n]))
  const nearest = (ids: string[]) =>
    ids
      .map((id) => byId.get(id))
      .filter((n): n is FlowKeyNode => !!n)
      .sort((a, b) => Math.abs(a.y - here.y) - Math.abs(b.y - here.y) || readingOrder(a, b))[0]
      ?.id ?? null

  switch (key) {
    case 'ArrowRight':
      return nearest(edges.filter((e) => e.source === here.id).map((e) => e.target))
    case 'ArrowLeft':
      return nearest(edges.filter((e) => e.target === here.id).map((e) => e.source))
    case 'ArrowDown':
    case 'ArrowUp': {
      const column = nodes.filter((n) => Math.abs(n.x - here.x) < 1).sort((a, b) => a.y - b.y)
      const i = column.findIndex((n) => n.id === here.id)
      const next = column[key === 'ArrowDown' ? i + 1 : i - 1]
      return next?.id ?? null
    }
    default:
      return null
  }
}
