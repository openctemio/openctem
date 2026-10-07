/**
 * Shared flow-canvas connection helpers (scan workflow builder and
 * Automations canvas). Each feature brings its own rule; these are the
 * engine-neutral parts: cycle detection and the adapter from a rule to
 * React Flow's `isValidConnection`.
 *
 * The client check is an affordance only. The API validates every save.
 */

export interface FlowEdgeLike {
  source: string
  target: string
}

/** Verdict of a connection rule. A refusal carries a plain reason. */
export type ConnectionVerdict =
  { ok: true; warning?: string } | { ok: false; reason: string; adapter?: string }

/**
 * True when adding source → target to edges closes a cycle (target already
 * reaches source).
 */
export function wouldCreateCycle(edges: FlowEdgeLike[], source: string, target: string): boolean {
  if (source === target) return true
  const next = new Map<string, string[]>()
  for (const e of edges) {
    const list = next.get(e.source)
    if (list) list.push(e.target)
    else next.set(e.source, [e.target])
  }
  const seen = new Set<string>()
  const stack = [target]
  while (stack.length > 0) {
    const n = stack.pop()!
    if (n === source) return true
    if (seen.has(n)) continue
    seen.add(n)
    for (const m of next.get(n) ?? []) stack.push(m)
  }
  return false
}

/**
 * Adapts a rule to React Flow's `isValidConnection` (a boolean while the
 * user drags). The last refusal is kept so the caller can explain it when
 * the drag ends.
 */
export function makeIsValidConnection(
  rule: (source: string, target: string) => ConnectionVerdict
): {
  isValidConnection: (c: { source: string | null; target: string | null }) => boolean
  lastRefusal: () => (ConnectionVerdict & { ok: false }) | null
} {
  let last: (ConnectionVerdict & { ok: false }) | null = null
  return {
    isValidConnection: (c) => {
      if (!c.source || !c.target) return false
      const v = rule(c.source, c.target)
      last = v.ok ? null : v
      return v.ok
    },
    lastRefusal: () => last,
  }
}
