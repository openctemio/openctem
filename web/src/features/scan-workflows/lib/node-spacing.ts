/**
 * Moves canvas nodes down until no two of them overlap.
 *
 * Saved and auto-laid-out positions assume a short step card, but a step card
 * grows with its tool, timeout and capability rows: on a template with four
 * parallel steps the cards were drawn on top of each other. The canvas calls
 * this once the cards are measured; a node that does not overlap keeps its
 * position, and nothing moves sideways.
 */
export interface SpacedNode {
  id: string
  x: number
  y: number
  width: number
  height: number
}

export function spreadOverlapping(nodes: SpacedNode[], gap = 24): Map<string, number> {
  const moved = new Map<string, number>()
  const placed: SpacedNode[] = []
  const order = [...nodes].sort((a, b) => a.y - b.y || a.x - b.x)
  for (const n of order) {
    let y = n.y
    // Each push can create a new overlap with a node placed further down.
    for (let changed = true; changed;) {
      changed = false
      for (const p of placed) {
        const sideBySide = n.x < p.x + p.width && n.x + n.width > p.x
        const stacked = y < p.y + p.height && y + n.height > p.y
        if (sideBySide && stacked) {
          y = p.y + p.height + gap
          changed = true
        }
      }
    }
    if (y !== n.y) moved.set(n.id, y)
    placed.push({ ...n, y })
  }
  return moved
}
