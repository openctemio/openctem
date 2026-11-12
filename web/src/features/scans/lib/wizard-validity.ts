/**
 * What the scan wizard (New and Edit) knows about each step's validity, from
 * the same checks the API repeats on save: the form's own rules
 * (scan-form.ts) and, on Targets, the server's scope check read through
 * scanReadiness. Pure; the shell decides when a problem is shown.
 * Design: research/418.
 */

import type { ScanWizardStep } from '../components/new-scan/scan-stepper'
import type { ScanReadiness } from '../components/target-picker/selection-summary'
import type { NewScanFormData } from '../types'
import { basicInfoError, optionsError, scheduleError, targetsError } from './scan-form'
import { targetsNextBlock } from './targets-step'
import { enTranslate, type Translate } from './translate'
import type { WorkflowReadiness } from '@/features/scan-workflows/lib/readiness'

/**
 * How many of a workflow's steps a run would take now: every step whose
 * tool can run (ready, or waiting for a sensor to come online), out of all.
 * Informational only (owner decision 2026-11-04): a scan is always saved and
 * a run takes the steps that have a tool and a sensor, skipping the others
 * with their reason. Null while unknown.
 */
export function stepsThatRun(
  readiness: WorkflowReadiness | null | undefined
): { run: number; total: number } | null {
  if (!readiness || readiness.steps.length === 0) return null
  const run = readiness.steps.filter((s) => s.state === 'ready' || s.state === 'waiting').length
  return { run, total: readiness.steps.length }
}

export type StepIssues = Record<ScanWizardStep, string[]>

export type StepState = 'idle' | 'valid' | 'invalid'

export interface StepStatus {
  state: StepState
  /** Problems shown on the step (0 when valid or not shown yet). */
  count: number
}

/** Every step's problems; Review has none of its own (it shows them all). */
export function scanStepIssues(
  form: NewScanFormData,
  opts: {
    readiness?: ScanReadiness
    requireFuture?: boolean
    t?: Translate
  } = {}
): StepIssues {
  const t = opts.t ?? enTranslate
  const only = (...xs: (string | null)[]) => xs.filter((x): x is string => !!x)
  return {
    basic: only(basicInfoError(form, t)),
    targets: only(
      targetsError(form, t),
      opts.readiness ? targetsNextBlock(opts.readiness, t) : null
    ),
    options: only(optionsError(form, t)),
    schedule: only(scheduleError(form, { requireFuture: opts.requireFuture ?? true }, t)),
    review: [],
  }
}

/** The first problem in step order, or null when every step is valid. */
export function firstIssue(
  issues: StepIssues,
  steps: readonly ScanWizardStep[]
): { step: ScanWizardStep; message: string } | null {
  for (const step of steps) {
    const message = issues[step]?.[0]
    if (message) return { step, message }
  }
  return null
}

/** Total problems over the given steps. */
export function issueCount(issues: StepIssues, steps: readonly ScanWizardStep[]): number {
  return steps.reduce((n, s) => n + (issues[s]?.length ?? 0), 0)
}

/**
 * What the stepper shows per step: problems only on a step the person has
 * left (or on every step after a create attempt), so a dialog does not open
 * covered in warnings; a visited step without problems is valid; the rest are
 * idle (their number).
 */
export function stepStatuses(
  issues: StepIssues,
  steps: readonly ScanWizardStep[],
  seen: ReadonlySet<ScanWizardStep>,
  showAll: boolean
): Record<ScanWizardStep, StepStatus> {
  const out = {} as Record<ScanWizardStep, StepStatus>
  for (const step of steps) {
    const count = issues[step]?.length ?? 0
    const shown = showAll || seen.has(step)
    out[step] =
      !shown || step === 'review'
        ? { state: 'idle', count: 0 }
        : count > 0
          ? { state: 'invalid', count }
          : { state: 'valid', count: 0 }
  }
  return out
}

/**
 * Jobs a run is split into for its direct targets: one job per
 * `perJob` targets (asset group members are added at run time).
 */
export function estimateJobs(directTargets: number, perJob: number): number {
  if (directTargets <= 0) return 0
  return Math.ceil(directTargets / Math.max(1, perJob || 10))
}
