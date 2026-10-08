/**
 * Step keys: the stable id of a step inside its workflow. Dependencies,
 * run history and the data hops between steps refer to a step by its key,
 * so a key is made once (from what the step does) and never follows the
 * step's display name. The API refuses a change of a saved step's key once
 * the workflow has runs; the editors keep saved keys read-only.
 */

import type { ScanWorkflowStep } from '@/lib/api'
import { slugify } from '@/lib/utils'

/** What the API accepts (ValidateIdentifier, step_key max 100). */
export const STEP_KEY_PATTERN = /^[A-Za-z0-9_-]{1,100}$/

/** A key base from a capability key, tool or name: "resolve.dns" -> "resolve-dns". */
export function stepKeyBase(text: string | undefined): string {
  return slugify((text ?? '').replace(/[._]+/g, ' '), 40) || 'step'
}

/** base, or base-2, base-3, ... : the first one no other step uses. */
export function uniqueStepKey(base: string, taken: Iterable<string>): string {
  const used = new Set(taken)
  const root = base || 'step'
  if (!used.has(root)) return root
  for (let n = 2; ; n++) {
    const key = `${root}-${n}`
    if (!used.has(key)) return key
  }
}

/** Why a key cannot be saved, or undefined. */
export function stepKeyError(key: string, otherKeys: Iterable<string>): string | undefined {
  if (!key.trim()) return 'A step key is required.'
  if (!STEP_KEY_PATTERN.test(key)) return 'Use letters, digits, - and _ only (at most 100).'
  for (const k of otherKeys) if (k === key) return 'Another step already uses this key.'
  return undefined
}

/** The steps with one step's key changed, and every dependency on it moved. */
export function renameStepKey(
  steps: ScanWorkflowStep[],
  stepId: string,
  newKey: string
): ScanWorkflowStep[] {
  const old = steps.find((s) => s.id === stepId)?.step_key
  if (old === undefined || old === newKey) return steps
  return steps.map((s) => ({
    ...s,
    step_key: s.id === stepId ? newKey : s.step_key,
    depends_on: (s.depends_on ?? []).map((d) => (d === old ? newKey : d)),
  }))
}

/** The steps without one step; nothing depends on it any more. */
export function removeStep(steps: ScanWorkflowStep[], stepId: string): ScanWorkflowStep[] {
  const gone = steps.find((s) => s.id === stepId)?.step_key
  return steps
    .filter((s) => s.id !== stepId)
    .map((s, idx) => ({
      ...s,
      order: idx + 1,
      depends_on: (s.depends_on ?? []).filter((d) => d !== gone),
    }))
}
