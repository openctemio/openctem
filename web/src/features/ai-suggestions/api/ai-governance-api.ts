'use client'

/**
 * AI governance (API docs: architecture/ai-analysis.md): the organization's
 * AI use cases, a finding's AI suggestions, the run that produced them, and
 * the apply, dismiss and undo actions.
 *
 * The wire types are written here, not taken from the generated contract,
 * while the API change lands separately. Every read answers `null` when the
 * route is not there yet (404) or the caller may not read it (403): the
 * console then renders nothing instead of an error.
 *
 * Every free-text field (a reason, a step, a summary, an evidence quote) is
 * model output: render it with `AIModelText`, never as markdown or HTML.
 */
import useSWR from 'swr'

import { get, post, put } from '@/lib/api/client'
import { ApiClientError } from '@/lib/api/error-handler'

export type AIUseCase = 'triage' | 'remediation' | 'summary'
export type AIMode = 'off' | 'suggest' | 'auto_apply'
export type AIExecutor = 'builtin' | 'platform_worker' | 'tenant_worker'
export type AIDataClass = 'public' | 'internal' | 'restricted' | 'tenant_only'
export type AITrigger = 'on_demand' | 'on_ingest' | 'workflow' | 'schedule'

export interface AIUseCasePolicy {
  use_case: AIUseCase
  mode: AIMode
  /** What applies now: `off` while the organization has not consented to AI. */
  effective_mode: AIMode
  consented: boolean
  executor: AIExecutor
  data_class_ceiling: AIDataClass
  min_confidence: number
  triggers: AITrigger[]
  budget_share: number
  downgraded_at?: string
  downgrade_reason?: string
  updated_at?: string
  updated_by?: string
}

export interface AIUseCaseList {
  data: AIUseCasePolicy[]
  /** Share of overridden suggestions (0..1) that turns auto-apply back to suggest. */
  downgrade_threshold: number
  /** How many recent decisions the share is measured over. */
  downgrade_window: number
}

/** A partial change: omitted fields keep their value. */
export interface AIUseCasePatch {
  mode?: AIMode
  data_class_ceiling?: AIDataClass
  min_confidence?: number
  triggers?: AITrigger[]
  budget_share?: number
}

export type AISuggestionKind = 'verdict' | 'severity' | 'remediation_steps' | 'summary'
export type AIDirection = 'additive' | 'raises_risk' | 'lowers_risk'
export type AISuggestionState =
  | 'open'
  | 'applied'
  | 'auto_applied'
  | 'pending_approval'
  | 'dismissed'
  | 'superseded'
  | 'undone'
  | 'needs_review'
  | 'shadow'

export interface AIEvidence {
  ref: string
  quote?: string
}

export interface AIRunShort {
  executor: AIExecutor
  provider?: string
  model?: string
  prompt_template_id?: string
}

export interface AISuggestion {
  id: string
  run_id: string
  use_case: AIUseCase
  subject_type: string
  subject_id: string
  kind: AISuggestionKind
  /** Typed per kind on the server; read defensively (see suggestion-payload.ts). */
  payload: unknown
  schema_version?: string
  direction: AIDirection
  confidence?: number
  evidence: AIEvidence[]
  state: AISuggestionState
  review_reasons: string[]
  approval_kind?: 'status' | 'severity'
  approval_id?: string
  applied_by?: string
  applied_at?: string
  undone_by?: string
  undone_at?: string
  created_at: string
  origin: 'ai'
  run?: AIRunShort
}

export interface AIRun {
  id: string
  use_case: AIUseCase
  kind: string
  subject_type: string
  subject_id: string
  executor: AIExecutor
  status: string
  data_class: AIDataClass
  fields_sent: string[]
  fields_withheld: string[]
  bundle_digest?: string
  prompt_template_id?: string
  prompt_template_digest?: string
  output_schema?: string
  provider?: string
  model?: string
  tokens_in: number
  tokens_out: number
  cost_micro_usd: number
  duration_ms?: number
  error_code?: string
  trigger: string
  requested_by?: string
  created_at: string
  completed_at?: string
  suggestions: AISuggestion[]
}

export interface AIDecision {
  suggestion: AISuggestion
  pending_approval: boolean
}

export interface AIUndoRunResult {
  undone: number
  conflicts: number
  pending: number
}

export const AI_USE_CASES_URL = '/api/v1/organization/settings/ai/use-cases'

export const AI_ERR_CONSENT_REQUIRED = 'AI_CONSENT_REQUIRED'
export const AI_ERR_UNDO_CONFLICT = 'AI_UNDO_CONFLICT'
export const AI_ERR_DECIDED = 'AI_SUGGESTION_DECIDED'

export function findingSuggestionsUrl(findingId: string): string {
  return `/api/v1/findings/${encodeURIComponent(findingId)}/ai/suggestions`
}

export function aiRunUrl(runId: string): string {
  return `/api/v1/ai/runs/${encodeURIComponent(runId)}`
}

function suggestionActionUrl(id: string, action: 'apply' | 'dismiss' | 'undo'): string {
  return `/api/v1/ai/suggestions/${encodeURIComponent(id)}/${action}`
}

/** True for an error that means "this feature is not available here". */
export function isUnavailable(err: unknown): boolean {
  return err instanceof ApiClientError && (err.statusCode === 404 || err.statusCode === 403)
}

/** GET that answers null when the route is missing or not readable. */
async function getOrNull<T>(url: string): Promise<T | null> {
  try {
    return await get<T>(url)
  } catch (err) {
    if (isUnavailable(err)) return null
    throw err
  }
}

const READ_OPTIONS = { revalidateOnFocus: false, shouldRetryOnError: false } as const

/** The organization's AI use cases; null until the API has them. */
export function useAIUseCases(enabled: boolean) {
  return useSWR<AIUseCaseList | null>(
    enabled ? AI_USE_CASES_URL : null,
    (url: string) => getOrNull<AIUseCaseList>(url),
    READ_OPTIONS
  )
}

/** Needs a recent sign-in when it turns auto-apply on or raises the ceiling (the shared client asks). */
export async function updateAIUseCase(
  useCase: AIUseCase,
  patch: AIUseCasePatch
): Promise<AIUseCasePolicy> {
  return put<AIUseCasePolicy>(`${AI_USE_CASES_URL}/${encodeURIComponent(useCase)}`, patch)
}

/** A finding's AI suggestions; null when the API, the module or the permission is missing. */
export function useFindingAISuggestions(findingId: string | null) {
  return useSWR<AISuggestion[] | null>(
    findingId ? findingSuggestionsUrl(findingId) : null,
    async (url: string) => (await getOrNull<{ data: AISuggestion[] }>(url))?.data ?? null,
    READ_OPTIONS
  )
}

/** One run's provenance (the "Why" drawer). */
export function useAIRun(runId: string | null) {
  return useSWR<AIRun | null>(
    runId ? aiRunUrl(runId) : null,
    (url: string) => getOrNull<AIRun>(url),
    READ_OPTIONS
  )
}

export async function applyAISuggestion(id: string, closureReason?: string): Promise<AIDecision> {
  return post<AIDecision>(
    suggestionActionUrl(id, 'apply'),
    closureReason ? { closure_reason: closureReason } : {}
  )
}

export async function dismissAISuggestion(id: string): Promise<AIDecision> {
  return post<AIDecision>(suggestionActionUrl(id, 'dismiss'), {})
}

export async function undoAISuggestion(id: string): Promise<AIDecision> {
  return post<AIDecision>(suggestionActionUrl(id, 'undo'), {})
}

export async function undoAIRun(runId: string): Promise<AIUndoRunResult> {
  return post<AIUndoRunResult>(`${aiRunUrl(runId)}/undo`, {})
}
