/**
 * The stages of a scan workflow, from its dependency graph: stage N holds
 * the steps whose longest chain of dependencies has N steps, so the steps
 * of one stage can run in parallel. Used by every read-only view of a
 * workflow (detail sheet, New-scan preview, template library, run page).
 *
 * Display only: the API decides what runs (stage.ValidateGraph refuses a
 * cycle or a dependency on a missing step at save).
 */

import type { ScanWorkflowStep } from '@/lib/api'

const DEFAULT_TIMEOUT = 3600

export interface StagesProblem {
  kind: 'cycle' | 'missing'
  /** Step keys involved (the cycle, or the steps with a missing dependency). */
  steps: string[]
  /** For "missing": the dependency keys no step has. */
  missing?: string[]
}

export interface WorkflowStagesPlan {
  /** Stages in order; each is the steps that may run together. */
  stages: ScanWorkflowStep[][]
  /** Steps a step waits for, by step key (its dependencies, in order). */
  waitsFor: Record<string, string[]>
  /** The widest stage: how many steps can run at once. */
  maxConcurrent: number
  /** The longest chain by step timeouts, first to last. */
  criticalPath: ScanWorkflowStep[]
  /** Upper bound of a run: the critical path's step timeouts summed. */
  estimatedSeconds: number
  /** Why the graph is not a valid workflow, if it is not. */
  problems: StagesProblem[]
}

export function planStages(steps: ScanWorkflowStep[]): WorkflowStagesPlan {
  const byKey = new Map(steps.map((s) => [s.step_key, s]))
  const problems: StagesProblem[] = []
  const deps = new Map<string, string[]>()
  const missing = new Set<string>()
  const withMissing: string[] = []
  for (const s of steps) {
    const known: string[] = []
    let hasMissing = false
    for (const d of s.depends_on ?? []) {
      if (byKey.has(d)) known.push(d)
      else {
        missing.add(d)
        hasMissing = true
      }
    }
    if (hasMissing) withMissing.push(s.step_key)
    deps.set(s.step_key, known)
  }
  if (withMissing.length > 0) {
    problems.push({ kind: 'missing', steps: withMissing, missing: [...missing] })
  }

  // Kahn: a step's stage is one more than its latest dependency's.
  const level = new Map<string, number>()
  const indegree = new Map<string, number>()
  const next = new Map<string, string[]>()
  for (const s of steps) {
    indegree.set(s.step_key, (deps.get(s.step_key) ?? []).length)
    for (const d of deps.get(s.step_key) ?? []) {
      next.set(d, [...(next.get(d) ?? []), s.step_key])
    }
  }
  const queue = steps.filter((s) => indegree.get(s.step_key) === 0).map((s) => s.step_key)
  for (const k of queue) level.set(k, 0)
  // finish = earliest finish by timeouts along the longest chain
  const finish = new Map<string, number>()
  const prevOnPath = new Map<string, string | undefined>()
  for (let i = 0; i < queue.length; i++) {
    const k = queue[i]
    const step = byKey.get(k)!
    let start = 0
    let prev: string | undefined
    for (const d of deps.get(k) ?? []) {
      if ((finish.get(d) ?? 0) > start) {
        start = finish.get(d) ?? 0
        prev = d
      }
    }
    finish.set(k, start + (step.timeout_seconds || DEFAULT_TIMEOUT))
    prevOnPath.set(k, prev)
    for (const n of next.get(k) ?? []) {
      level.set(n, Math.max(level.get(n) ?? 0, (level.get(k) ?? 0) + 1))
      indegree.set(n, (indegree.get(n) ?? 0) - 1)
      if (indegree.get(n) === 0) queue.push(n)
    }
  }
  const onCycle = steps.filter((s) => !finish.has(s.step_key)).map((s) => s.step_key)
  if (onCycle.length > 0) problems.push({ kind: 'cycle', steps: onCycle })

  const stages: ScanWorkflowStep[][] = []
  for (const s of steps) {
    if (!finish.has(s.step_key)) continue
    const l = level.get(s.step_key) ?? 0
    ;(stages[l] ??= []).push(s)
  }
  const compact = stages.filter((g) => g && g.length > 0)

  let last: string | undefined
  for (const [k, f] of finish) {
    if (last === undefined || f > (finish.get(last) ?? 0)) last = k
  }
  const criticalPath: ScanWorkflowStep[] = []
  for (let k = last; k !== undefined; k = prevOnPath.get(k)) criticalPath.unshift(byKey.get(k)!)

  const waitsFor: Record<string, string[]> = {}
  for (const s of steps) waitsFor[s.step_key] = deps.get(s.step_key) ?? []

  return {
    stages: compact,
    waitsFor,
    maxConcurrent: Math.max(0, ...compact.map((g) => g.length)),
    criticalPath,
    estimatedSeconds: last === undefined ? 0 : (finish.get(last) ?? 0),
    problems,
  }
}

/** "1 h 30 min", "45 min", "30 s". */
export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds} s`
  const h = Math.floor(seconds / 3600)
  const m = Math.round((seconds % 3600) / 60)
  if (h === 0) return `${m} min`
  return m === 0 ? `${h} h` : `${h} h ${m} min`
}
