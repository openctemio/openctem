/**
 * Workflow readiness, as the API computes it for the caller's organization
 * (GET /scan-workflows?include=readiness): whether a workflow can run now
 * and why not, per step. The API refuses a scan of a workflow that cannot
 * run; the UI only shows the same answer.
 */

export type ReadinessState = 'ready' | 'waiting' | 'ci_only' | 'blocked'

export interface StepReadiness {
  step_key: string
  name: string
  capability?: string
  state: ReadinessState
  reason?: string
  fix?: string
}

export interface WorkflowReadiness {
  state: ReadinessState
  steps: StepReadiness[]
}

/** A scan may be created (unknown readiness counts as runnable). */
export function isRunnable(r: WorkflowReadiness | undefined | null): boolean {
  return !r || r.state === 'ready' || r.state === 'waiting'
}

/** The first step that keeps the workflow from running as it is. */
export function firstProblem(r: WorkflowReadiness | undefined | null): StepReadiness | undefined {
  if (!r) return undefined
  const order: ReadinessState[] = ['blocked', 'ci_only', 'waiting']
  for (const state of order) {
    const step = r.steps.find((s) => s.state === state)
    if (step) return step
  }
  return undefined
}

/** A short label for a workflow that is not plainly ready. */
export function readinessLabel(r: WorkflowReadiness | undefined | null): string | undefined {
  switch (r?.state) {
    case 'waiting':
      return 'No capable sensor online'
    case 'ci_only':
      return 'Runs in your CI pipeline'
    case 'blocked':
      return 'Not available'
    default:
      return undefined
  }
}

/** Where the fix of a workflow that cannot run is done. */
export function readinessFixHref(r: WorkflowReadiness | undefined | null): string | undefined {
  const step = firstProblem(r)
  if (!step) return undefined
  if (step.state === 'ci_only') return '/ci-cd'
  if ((step.fix ?? '').startsWith('Enable')) return '/settings/scanning/tools'
  if (step.state === 'blocked' || step.state === 'waiting') return '/sensors'
  return undefined
}

/** Runnable workflows first (ready, then waiting), then the others; stable. */
export function byReadiness<T extends { readiness?: WorkflowReadiness | null }>(items: T[]): T[] {
  const rank: Record<ReadinessState, number> = { ready: 0, waiting: 1, ci_only: 2, blocked: 3 }
  return items
    .map((item, i) => ({ item, i }))
    .sort(
      (a, b) =>
        rank[a.item.readiness?.state ?? 'ready'] - rank[b.item.readiness?.state ?? 'ready'] ||
        a.i - b.i
    )
    .map((x) => x.item)
}
