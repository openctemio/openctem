/**
 * Pure helpers for the automation lifecycle on the canvas: which catalog
 * entries a step kind offers, whether a stored node uses a removed type,
 * what going live needs, who may approve a pending version and how preview
 * or trace counts land on the steps. Design: api/docs/rfcs/RFC-125-automation-simulate-and-go-live.md.
 *
 * The API is the authority for every one of these decisions; the web only
 * explains them before the call.
 */
import type {
  AutomationRiskClass,
  NodeRun,
  Workflow,
  WorkflowCatalog,
  WorkflowCatalogEntry,
  WorkflowNodeConfig,
  WorkflowNodeType,
  WorkflowStepTrace,
} from '@/lib/api/workflow-types'

/** The catalog list behind a step kind; conditions have none. */
export function catalogEntriesFor(
  catalog: WorkflowCatalog | undefined,
  kind: WorkflowNodeType | string | undefined
): WorkflowCatalogEntry[] {
  if (!catalog) return []
  if (kind === 'trigger') return catalog.triggers ?? []
  if (kind === 'action') return catalog.actions ?? []
  if (kind === 'notification') return catalog.notifications ?? []
  return []
}

/** The type id a node is set to (trigger, action or notification type). */
export function nodeTypeId(
  kind: WorkflowNodeType | string | undefined,
  config: WorkflowNodeConfig | undefined
): string | undefined {
  if (!config) return undefined
  if (kind === 'trigger') return config.trigger_type || undefined
  if (kind === 'action') return config.action_type || undefined
  if (kind === 'notification') return config.notification_type || undefined
  return undefined
}

/**
 * The type id when a node uses a type the catalog does not list (removed or
 * unknown), else undefined. Nothing is flagged until the catalog has loaded.
 */
export function removedTypeOf(
  catalog: WorkflowCatalog | undefined,
  kind: WorkflowNodeType | string | undefined,
  config: WorkflowNodeConfig | undefined
): string | undefined {
  if (!catalog || kind === 'condition') return undefined
  const id = nodeTypeId(kind, config)
  if (!id) return undefined
  return catalogEntriesFor(catalog, kind).some((e) => e.type === id) ? undefined : id
}

export interface PublishRequirements {
  /** A fresh sign-in (step-up) before publishing. */
  stepUp: boolean
  /** A second person with automations:publish approves this version. */
  secondApprover: boolean
}

/** What publishing a rule of this risk class needs (RFC-125 go-live gate). */
export function publishRequirements(
  risk: AutomationRiskClass | undefined | null
): PublishRequirements {
  if (risk === 'high') return { stepUp: true, secondApprover: true }
  if (risk === 'elevated') return { stepUp: true, secondApprover: false }
  return { stepUp: false, secondApprover: false }
}

export type ApprovalState =
  /** Nothing is waiting. */
  | 'none'
  /** The viewer may approve the pending version. */
  | 'can_approve'
  /** The viewer published it; someone else must approve. */
  | 'self'
  /** The viewer lacks automations:publish. */
  | 'no_permission'

/** Whether the viewer may approve the automation's pending version. */
export function approvalState(
  workflow: Pick<Workflow, 'pending_version'>,
  viewerId: string | undefined,
  canPublish: boolean
): ApprovalState {
  const pending = workflow.pending_version
  if (!pending) return 'none'
  if (viewerId && pending.published_by === viewerId) return 'self'
  if (!canPublish) return 'no_permission'
  return 'can_approve'
}

/** Counts of one step as drawn on the canvas. */
export interface StepCount {
  in: number
  out: number
  skipped: Record<string, number>
}

/** Preview or trace steps keyed by node key. */
export function countsFromSteps(steps: WorkflowStepTrace[] | undefined): Map<string, StepCount> {
  const out = new Map<string, StepCount>()
  for (const s of steps ?? []) {
    out.set(s.node_key, { in: s.in ?? 0, out: s.out ?? 0, skipped: s.skipped ?? {} })
  }
  return out
}

/** One run's node runs keyed by node key. */
export function countsFromNodeRuns(runs: NodeRun[] | undefined): Map<string, StepCount> {
  const out = new Map<string, StepCount>()
  for (const r of runs ?? []) {
    out.set(r.node_key, { in: r.in_count ?? 0, out: r.out_count ?? 0, skipped: r.skipped ?? {} })
  }
  return out
}

/** The skipped reasons of a step, largest first. */
export function skippedEntries(skipped: Record<string, number> | undefined): [string, number][] {
  return Object.entries(skipped ?? {})
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1])
}

/** The validate problems a failed publish carries (400 WORKFLOW_INVALID). */
export function problemsFromError(
  err: unknown
): { code: string; node_key?: string; message: string }[] | null {
  if (!err || typeof err !== 'object') return null
  const e = err as { code?: string; details?: Record<string, unknown> }
  if (e.code !== 'WORKFLOW_INVALID') return null
  const raw = e.details?.problems
  if (!Array.isArray(raw)) return []
  return raw.filter(
    (p): p is { code: string; node_key?: string; message: string } =>
      !!p && typeof p === 'object' && typeof (p as { code?: unknown }).code === 'string'
  )
}

/** The API's error code of a refused call, if any. */
export function errorCode(err: unknown): string | undefined {
  if (!err || typeof err !== 'object') return undefined
  const c = (err as { code?: unknown }).code
  return typeof c === 'string' ? c : undefined
}

/** The HTTP status of a refused call, if any. */
export function errorStatus(err: unknown): number | undefined {
  if (!err || typeof err !== 'object') return undefined
  const s = (err as { statusCode?: unknown }).statusCode
  return typeof s === 'number' ? s : undefined
}
