import type { Severity } from '@/features/shared/types'
import type { HealthState } from '@/lib/health-colors'

/**
 * AI Triage status enum
 */
export type TriageStatus = 'pending' | 'processing' | 'completed' | 'failed'

/**
 * Exploitability assessment
 */
export type Exploitability = 'high' | 'medium' | 'low' | 'theoretical'

/**
 * Remediation step effort level
 */
export type RemediationEffort = 'low' | 'medium' | 'high'

/**
 * Remediation step from AI analysis
 */
export interface RemediationStep {
  step: number
  description: string
  effort: RemediationEffort
}

/**
 * AI Triage result from the API
 */
export interface AITriageResult {
  id: string
  findingId: string
  status: TriageStatus

  // Analysis results
  severityAssessment?: Severity
  severityJustification?: string
  riskScore?: number
  exploitability?: Exploitability
  exploitabilityDetails?: string
  businessImpact?: string
  priorityRank?: number
  falsePositiveLikelihood?: number
  falsePositiveReason?: string
  summary?: string

  // Recommendations
  remediationSteps?: RemediationStep[]
  relatedCves?: string[]
  relatedCwes?: string[]

  // Metadata
  llmProvider?: string
  llmModel?: string
  promptTokens?: number
  completionTokens?: number

  // Timestamps
  createdAt: string
  completedAt?: string
  /** Failure code of a failed triage; the UI translates it. */
  errorCode?: string
}

/**
 * An AI triage job is a machine's work, so its status is a health state
 * (research/247 section 4): pending queued, analyzing running, completed ok,
 * failed down. The map holds no classes.
 */
export const TRIAGE_STATUS_CONFIG: Record<TriageStatus, { label: string; health: HealthState }> = {
  pending: { label: 'Pending', health: 'queued' },
  processing: { label: 'Analyzing', health: 'run' },
  completed: { label: 'Completed', health: 'ok' },
  failed: { label: 'Failed', health: 'down' },
}

/** Exploitability as an ordinal level (bars and the word), not a colour. */
export const EXPLOITABILITY_CONFIG: Record<
  Exploitability,
  { label: string; level: 0 | 1 | 2 | 3 }
> = {
  high: { label: 'High', level: 3 },
  medium: { label: 'Medium', level: 2 },
  low: { label: 'Low', level: 1 },
  theoretical: { label: 'Theoretical', level: 0 },
}

/** Remediation effort as an ordinal level. */
export const EFFORT_CONFIG: Record<RemediationEffort, { label: string; level: 0 | 1 | 2 | 3 }> = {
  low: { label: 'Low Effort', level: 1 },
  medium: { label: 'Medium Effort', level: 2 },
  high: { label: 'High Effort', level: 3 },
}

/**
 * Request body for triggering AI triage
 */
export interface RequestTriageInput {
  mode?: 'quick' | 'detailed'
}

/**
 * Response from triggering AI triage
 */
export interface RequestTriageResponse {
  jobId: string
  status: TriageStatus
}

/**
 * Paginated triage history response
 */
export interface TriageHistoryResponse {
  data: AITriageResult[]
  total: number
  limit: number
  offset: number
}

/**
 * AI mode for the tenant
 */
export type AIMode = 'platform' | 'byok' | 'agent' | 'disabled'

/**
 * AI configuration info returned from the API
 */
/** Why AI triage cannot run for the organization (GET /findings/ai-triage/config). */
export type AIUnavailableReason =
  | 'not_enabled'
  | 'platform_not_configured'
  | 'own_provider_not_allowed'
  | 'own_provider_not_configured'
  | 'budget_exhausted'

export interface AIConfig {
  mode: AIMode
  provider: string
  model: string
  isEnabled: boolean
  reason?: AIUnavailableReason
  autoTriageEnabled: boolean
  autoTriageSeverities?: string[]
  monthlyTokenLimit: number
  tokensUsedThisMonth: number
}

/**
 * Provider display names
 */
export const PROVIDER_DISPLAY_NAMES: Record<string, string> = {
  claude: 'Claude',
  openai: 'OpenAI',
  gemini: 'Gemini',
  agent: 'Self-hosted',
}

/**
 * Mode display names
 */
export const MODE_DISPLAY_NAMES: Record<AIMode, string> = {
  platform: 'Platform AI',
  byok: 'Your API Key',
  agent: 'Self-hosted',
  disabled: 'Disabled',
}
