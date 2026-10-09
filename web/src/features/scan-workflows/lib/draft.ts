/**
 * A scan workflow's draft: what the builder saved last, valid or not. A
 * save always succeeds (the layout and edits are never lost); publishing
 * makes the draft the steps runs use and needs no blocking issue.
 */

import { del, get, post, put } from '@/lib/api/client'
import type { CreateStepRequest, ScanWorkflow, ScanWorkflowStep, UIPosition } from '@/lib/api'
import { generateTempStepId } from '@/lib/utils'
import type { GraphValidation } from './capability-graph'
import { roundPosition, toStepRequest } from './step-request'

export interface WorkflowDraft {
  steps: CreateStepRequest[]
  ui_start_position?: UIPosition
  ui_end_position?: UIPosition
  issues: GraphValidation
  updated_at: string
}

const draftUrl = (id: string) => `/api/v1/scan-workflows/${id}/draft`
const publishUrl = (id: string) => `/api/v1/scan-workflows/${id}/publish`

function isNotFound(err: unknown): boolean {
  const e = err as { status?: number; statusCode?: number } | undefined
  return e?.status === 404 || e?.statusCode === 404
}

/** The workflow's draft, or null when it has none. */
export async function fetchDraft(id: string): Promise<WorkflowDraft | null> {
  try {
    return await get<WorkflowDraft>(draftUrl(id))
  } catch (err) {
    if (isNotFound(err)) return null
    throw err
  }
}

/** Saves the draft; resolves with what its check found. */
export function saveDraft(
  id: string,
  steps: ScanWorkflowStep[],
  start?: UIPosition,
  end?: UIPosition
): Promise<WorkflowDraft> {
  return put<WorkflowDraft>(draftUrl(id), {
    steps: steps.map(toStepRequest),
    ui_start_position: roundPosition(start),
    ui_end_position: roundPosition(end),
  })
}

/** Saves already-serialized steps as the draft (the form). */
export function saveDraftSteps(id: string, steps: CreateStepRequest[]): Promise<WorkflowDraft> {
  return put<WorkflowDraft>(draftUrl(id), { steps })
}

export function publishDraft(id: string): Promise<ScanWorkflow> {
  return post<ScanWorkflow>(publishUrl(id), {})
}

export function discardDraft(id: string): Promise<void> {
  return del<void>(draftUrl(id))
}

/** A draft step as the editor holds it. */
export function fromDraftStep(s: CreateStepRequest, idx: number): ScanWorkflowStep {
  return {
    id: s.id || generateTempStepId(),
    step_key: s.step_key,
    name: s.name,
    description: s.description,
    order: s.order || idx + 1,
    ui_position: s.ui_position ?? { x: 0, y: 0 },
    tool: s.tool ?? '',
    capabilities: s.capabilities ?? [],
    prefer_tools: s.prefer_tools ?? [],
    config: s.config,
    timeout_seconds: s.timeout_seconds,
    depends_on: s.depends_on ?? [],
    condition: s.condition,
    max_retries: s.max_retries ?? 0,
    retry_delay_seconds: s.retry_delay_seconds ?? 0,
  }
}
