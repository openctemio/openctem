/**
 * What a save on Settings > Modules changes, worked out on the page from the
 * dependency graph it already loaded (research/394 §4): turning a module off
 * turns off every module that hard-requires it, turning one on turns on the
 * modules it hard-requires. The admin sees the whole set before saving, and
 * the save sends it in one request, so the API's dependency refusal is only a
 * fallback.
 *
 * Soft edges never cascade: the dependent keeps working with less.
 */
import type { DependencyEdge } from '@/features/organization/api/use-tenant-modules'

export interface DependencyIndex {
  /** id -> the modules it hard-requires. */
  requires: Record<string, string[]>
  /** id -> the modules that hard-require it. */
  requiredBy: Record<string, string[]>
}

export function buildDependencyIndex(edges: readonly DependencyEdge[]): DependencyIndex {
  const requires: Record<string, string[]> = {}
  const requiredBy: Record<string, string[]> = {}
  for (const e of edges) {
    if (e.type !== 'hard') continue
    ;(requires[e.from] ||= []).push(e.to)
    ;(requiredBy[e.to] ||= []).push(e.from)
  }
  return { requires, requiredBy }
}

/** Every module reachable from `id` through `next`, nearest first, without `id`. */
export function reachable(id: string, next: Record<string, string[]>): string[] {
  const seen = new Set<string>([id])
  const out: string[] = []
  const queue = [...(next[id] ?? [])]
  while (queue.length) {
    const cur = queue.shift()!
    if (seen.has(cur)) continue
    seen.add(cur)
    out.push(cur)
    queue.push(...(next[cur] ?? []))
  }
  return out
}

/**
 * The admin's choices after flipping `id` to `value`. Only differences from
 * the saved state are kept. The latest choice wins over an earlier one that
 * contradicts it: turning a module on drops an earlier "off" on anything it
 * needs, turning one off drops an earlier "on" on anything that needs it.
 */
export function applyToggle(
  pending: Readonly<Record<string, boolean>>,
  saved: Readonly<Record<string, boolean>>,
  id: string,
  value: boolean,
  index: DependencyIndex
): Record<string, boolean> {
  const next = { ...pending }
  if (saved[id] === value) delete next[id]
  else next[id] = value
  const related = value ? reachable(id, index.requires) : reachable(id, index.requiredBy)
  for (const r of related) {
    if (next[r] === !value) delete next[r]
  }
  return next
}

export interface PlanOptions {
  /** Core modules are always on and never part of a plan. */
  isCore: (id: string) => boolean
  /** False for a module this organization cannot switch on (not available, set by the installation). */
  canEnable: (id: string) => boolean
}

export interface ModulePlan {
  /** Every module the save changes (chosen plus cascaded), id -> new state. */
  changes: Record<string, boolean>
  /** Modules that turn off because a module they need turns off: id -> those modules. */
  offWith: Record<string, string[]>
  /** Modules that turn on because a module that needs them turns on: id -> those modules. */
  onWith: Record<string, string[]>
  /** Chosen modules that cannot turn on, id -> the required modules that cannot. */
  blocked: Record<string, string[]>
}

export function computePlan(
  saved: Readonly<Record<string, boolean>>,
  pending: Readonly<Record<string, boolean>>,
  index: DependencyIndex,
  opts: PlanOptions
): ModulePlan {
  const desired: Record<string, boolean> = { ...saved, ...pending }
  const offWith: Record<string, string[]> = {}
  const onWith: Record<string, string[]> = {}
  const blocked: Record<string, string[]> = {}

  for (const [root, value] of Object.entries(pending)) {
    if (value || opts.isCore(root)) continue
    for (const d of reachable(root, index.requiredBy)) {
      if (opts.isCore(d) || d in pending) continue
      if (desired[d] || offWith[d]) {
        desired[d] = false
        ;(offWith[d] ||= []).push(root)
      }
    }
  }
  for (const [root, value] of Object.entries(pending)) {
    if (!value || opts.isCore(root)) continue
    for (const r of reachable(root, index.requires)) {
      // Already on by itself: nothing to turn on.
      if (opts.isCore(r) || (desired[r] === true && !onWith[r])) continue
      if (!opts.canEnable(r)) {
        ;(blocked[root] ||= []).push(r)
        continue
      }
      desired[r] = true
      ;(onWith[r] ||= []).push(root)
    }
  }

  const changes: Record<string, boolean> = {}
  for (const [id, value] of Object.entries(desired)) {
    if (opts.isCore(id)) continue
    if ((saved[id] ?? false) !== value) changes[id] = value
  }
  return { changes, offWith, onWith, blocked }
}

/**
 * The required modules that keep `id` from turning on: off and not
 * available to this organization (their dependents are off with them).
 */
export function unavailableRequirements(
  id: string,
  saved: Readonly<Record<string, boolean>>,
  index: DependencyIndex,
  opts: PlanOptions
): string[] {
  return reachable(id, index.requires).filter(
    (r) => !opts.isCore(r) && !saved[r] && !opts.canEnable(r)
  )
}
