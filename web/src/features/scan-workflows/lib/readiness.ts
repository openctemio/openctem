/**
 * Workflow readiness, as the API computes it for the caller's organization
 * (GET /scan-workflows?include=readiness): whether a workflow can run now
 * and why not, per step. The API refuses a scan of a workflow that cannot
 * run; the UI only shows the same answer.
 */

export type ReadinessState = 'ready' | 'waiting' | 'ci_only' | 'blocked'

/**
 * A step's state adds `skipped`: an optional step that no installed tool
 * runs. A run skips it with the reason; it never blocks the workflow.
 */
export type StepReadinessState = ReadinessState | 'skipped'

/** Stable reason codes of the API (scan.Reason*). */
export type ReadinessReasonCode =
  | 'sensor_offline'
  | 'no_sensor_yet'
  | 'ci_only'
  | 'no_tool'
  | 'tool_disabled'
  | 'tool_not_installed'
  | 'no_sensor'

export interface StepReadiness {
  step_key: string
  name: string
  capability?: string
  state: StepReadinessState
  /** The run skips the step when no tool implements it. */
  optional?: boolean
  code?: ReadinessReasonCode | string
  /** Tools the reason and the fix name. */
  tools?: string[]
  /** English text from the API; the UI shows the localized reason. */
  reason?: string
  fix?: string
}

export interface WorkflowReadiness {
  state: ReadinessState
  steps: StepReadiness[]
}

type Translate = (key: string, fallback?: string, vars?: Record<string, string | number>) => string

/** A scan may be created (unknown readiness counts as runnable). */
export function isRunnable(r: WorkflowReadiness | undefined | null): boolean {
  return !r || r.state === 'ready' || r.state === 'waiting'
}

/** The first step that keeps the workflow from running as it is. */
export function firstProblem(r: WorkflowReadiness | undefined | null): StepReadiness | undefined {
  return problemSteps(r)[0]
}

/** The steps that keep the workflow from running as it is, worst first. */
export function problemSteps(r: WorkflowReadiness | undefined | null): StepReadiness[] {
  if (!r) return []
  const order: StepReadinessState[] = ['blocked', 'ci_only', 'waiting']
  return order.flatMap((state) => r.steps.filter((s) => s.state === state))
}

/** Optional steps a run leaves out until a tool for them is installed. */
export function skippedSteps(r: WorkflowReadiness | undefined | null): StepReadiness[] {
  return r?.steps.filter((s) => s.state === 'skipped') ?? []
}

/** A short label for a workflow that is not plainly ready. */
export function readinessLabel(
  r: WorkflowReadiness | undefined | null,
  t?: Translate
): string | undefined {
  const tr = (key: string, fallback: string) => (t ? t(key, fallback) : fallback)
  switch (r?.state) {
    case 'waiting':
      return tr('scans.readiness.label.waiting', 'No capable sensor online')
    case 'ci_only':
      return tr('scans.readiness.label.ciOnly', 'Runs in your CI pipeline')
    case 'blocked':
      return tr('scans.readiness.label.blocked', 'Not available')
    default:
      return undefined
  }
}

/** The step's reason in the reader's language (the API text as fallback). */
export function stepReason(step: StepReadiness, t: Translate): string | undefined {
  const capability = step.capability ?? step.name
  if (step.state === 'skipped') {
    return t('scans.readiness.skipped', step.reason ?? '', { capability })
  }
  if (!step.code) return step.reason
  const vars = { capability, tools: (step.tools ?? []).join(', ') }
  return t(`scans.readiness.reason.${step.code}`, step.reason ?? '', vars) || undefined
}

/**
 * The step's fix in the reader's language (the API text as fallback). A
 * skipped step has none: it runs once a tool for it is installed.
 */
export function stepFix(step: StepReadiness, t: Translate): string | undefined {
  if (step.state === 'skipped') return undefined
  if (!step.code) return step.fix
  const vars = { tools: (step.tools ?? []).join(', ') }
  return t(`scans.readiness.fix.${step.code}`, step.fix ?? '', vars) || undefined
}

/** The first problem's reason in the reader's language. */
export function problemText(
  r: WorkflowReadiness | undefined | null,
  t: Translate
): string | undefined {
  const step = firstProblem(r)
  return step ? stepReason(step, t) : undefined
}

/** Where one step's fix is done. */
export function stepFixHref(step: StepReadiness | undefined): string | undefined {
  if (!step || step.state === 'skipped') return undefined
  if (step.code === 'ci_only' || step.state === 'ci_only') return '/ci-cd'
  if (step.code === 'tool_disabled' || (step.fix ?? '').startsWith('Enable'))
    return '/settings/scanning/tools'
  if (step.state === 'blocked' || step.state === 'waiting') return '/sensors'
  return undefined
}

/** Where the fix of a workflow that cannot run is done. */
export function readinessFixHref(r: WorkflowReadiness | undefined | null): string | undefined {
  return stepFixHref(firstProblem(r))
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
