import type { AIRun } from '../api/use-ai-agents'

/**
 * The AI review state of a finding, read from its latest AI agent run (api
 * docs: architecture/ai-analysis.md). It sits beside the finding's status and
 * never replaces it: a person always decides the status.
 *
 * - waiting: the run is queued (for example, for an AI worker);
 * - reviewing: the run is in progress;
 * - changed: the AI agent changed the finding (applied);
 * - decide: a request or a held suggestion waits for a person (proposed);
 * - agrees: the AI agent only added information (no_change);
 * - unsure: nothing usable came back (abstained);
 * - not_reviewed: the run failed, was refused or canceled (reason = its code).
 */
export type AIReviewState =
  'waiting' | 'reviewing' | 'changed' | 'decide' | 'agrees' | 'unsure' | 'not_reviewed'

export interface AIReview {
  state: AIReviewState
  /** A fixed code (error code of a run that ended without a review). */
  reason?: string
  run: AIRun
}

const OUTCOME_STATE: Record<string, AIReviewState> = {
  applied: 'changed',
  proposed: 'decide',
  no_change: 'agrees',
  abstained: 'unsure',
}

/** The review of the latest run, or null when the finding has no run. */
export function aiReviewOf(runs: AIRun[] | undefined): AIReview | null {
  const run = runs?.[0]
  if (!run) return null
  switch (run.status) {
    case 'queued':
      return { state: 'waiting', run }
    case 'running':
    case 'waiting_tool':
    case 'waiting_approval':
      return { state: 'reviewing', run }
    case 'completed':
      return { state: OUTCOME_STATE[run.outcome ?? ''] ?? 'agrees', run }
    default:
      return { state: 'not_reviewed', reason: run.error_code || run.status, run }
  }
}

/** A code shown as words when no translation exists: "finding_changed" -> "finding changed". */
export function codeWords(code: string): string {
  return code.replace(/[^a-z0-9]+/gi, ' ').trim()
}
