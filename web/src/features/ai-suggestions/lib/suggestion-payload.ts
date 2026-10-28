/**
 * Reads a suggestion's payload defensively. The server decodes payloads
 * strictly per kind, but the console still treats them as untrusted: only
 * the expected string fields are read, anything else is ignored.
 */
import type { AISuggestion } from '../api/ai-governance-api'

export interface ReadPayload {
  verdict?: string
  severity?: string
  reason?: string
  text?: string
  steps: { description: string; effort?: string }[]
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() !== '' ? v : undefined
}

export function readPayload(s: Pick<AISuggestion, 'payload'>): ReadPayload {
  const p = (s.payload && typeof s.payload === 'object' ? s.payload : {}) as Record<string, unknown>
  const steps = Array.isArray(p.steps)
    ? p.steps
        .map((x) => (x && typeof x === 'object' ? (x as Record<string, unknown>) : {}))
        .map((x) => ({ description: str(x.description) ?? '', effort: str(x.effort) }))
        .filter((x) => x.description !== '')
    : []
  return {
    verdict: str(p.verdict),
    severity: str(p.severity),
    reason: str(p.reason),
    text: str(p.text),
    steps,
  }
}

/** A false-positive verdict: applying it closes the finding, so it needs a closure reason. */
export function isFalsePositiveVerdict(s: Pick<AISuggestion, 'kind' | 'payload'>): boolean {
  return s.kind === 'verdict' && readPayload(s).verdict === 'likely_false_positive'
}

/** States shown on the finding: still to decide, or decided and undoable or waiting. */
export const VISIBLE_STATES: ReadonlySet<string> = new Set([
  'open',
  'needs_review',
  'pending_approval',
  'applied',
  'auto_applied',
])

export const KIND_ORDER: AISuggestion['kind'][] = [
  'verdict',
  'severity',
  'remediation_steps',
  'summary',
]
