/**
 * Editing what a step runs after, in the form: the dependencies that make
 * the stages (planStages). Every change keeps the graph free of loops; the
 * API checks the graph again on save.
 */

import type { ScanWorkflowStep } from '@/lib/api'
import type { WorkflowStagesPlan } from './workflow-stages'

/** The keys a step waits for, directly or through other steps. */
function ancestors(steps: ScanWorkflowStep[], key: string): Set<string> {
  const byKey = new Map(steps.map((s) => [s.step_key, s]))
  const seen = new Set<string>()
  const queue = [...(byKey.get(key)?.depends_on ?? [])]
  while (queue.length > 0) {
    const k = queue.pop()!
    if (seen.has(k)) continue
    seen.add(k)
    queue.push(...(byKey.get(k)?.depends_on ?? []))
  }
  return seen
}

/**
 * Whether `step` may run after `candidate`: not itself, and `candidate`
 * does not already wait for `step` (that would make a loop).
 */
export function canRunAfter(
  steps: ScanWorkflowStep[],
  stepKey: string,
  candidateKey: string
): boolean {
  if (stepKey === candidateKey) return false
  return !ancestors(steps, candidateKey).has(stepKey) && candidateKey !== stepKey
}

/** The steps with one step's dependencies replaced; refused keys are left out. */
export function setRunsAfter(
  steps: ScanWorkflowStep[],
  stepId: string,
  keys: string[]
): ScanWorkflowStep[] {
  const step = steps.find((s) => s.id === stepId)
  if (!step) return steps
  const allowed = keys.filter(
    (k, i) => keys.indexOf(k) === i && canRunAfter(steps, step.step_key, k)
  )
  return steps.map((s) => (s.id === stepId ? { ...s, depends_on: allowed } : s))
}

/**
 * Moves a step into the stage of another (a drag in the form): it takes the
 * other step's dependencies. Refused, with the reason, when that would make
 * a loop (the other step already waits for it, directly or not).
 */
export function moveToStageOf(
  steps: ScanWorkflowStep[],
  stepId: string,
  overId: string
): { steps: ScanWorkflowStep[]; error?: string } {
  const step = steps.find((s) => s.id === stepId)
  const over = steps.find((s) => s.id === overId)
  if (!step || !over || step.id === over.id) return { steps }
  const deps = (over.depends_on ?? []).filter((k) => k !== step.step_key)
  const loop = deps.find((k) => !canRunAfter(steps, step.step_key, k))
  if (loop) {
    const name = steps.find((s) => s.step_key === loop)?.name || loop
    return {
      steps,
      error: `${name} already runs after ${step.name || step.step_key}: that would make a loop.`,
    }
  }
  return { steps: steps.map((s) => (s.id === stepId ? { ...s, depends_on: deps } : s)) }
}

/**
 * Stage labels by step key: "1" for a step alone in its stage, "1a", "1b"
 * for parallel steps.
 */
export function stageLabels(plan: WorkflowStagesPlan): Record<string, string> {
  const out: Record<string, string> = {}
  plan.stages.forEach((stage, i) => {
    stage.forEach((s, j) => {
      out[s.step_key] =
        stage.length === 1 ? `${i + 1}` : `${i + 1}${String.fromCharCode(97 + (j % 26))}`
    })
  })
  return out
}
