import type { AIConfig, AIMode, AIUnavailableReason } from '../types'
import type { ApiAIConfigResponse } from '../api/ai-triage-api.types'

export const AI_CONFIG_ENDPOINT = '/api/v1/findings/ai-triage/config'

/** Transform the API AI config (also carried by GET /me/bootstrap) to the domain type. */
export function transformAIConfig(api: ApiAIConfigResponse): AIConfig {
  return {
    mode: api.mode as AIMode,
    provider: api.provider,
    model: api.model,
    isEnabled: api.is_enabled,
    reason: (api.reason || undefined) as AIUnavailableReason | undefined,
    autoTriageEnabled: api.auto_triage_enabled,
    autoTriageSeverities: api.auto_triage_severities,
    monthlyTokenLimit: api.monthly_token_limit,
    tokensUsedThisMonth: api.tokens_used_this_month,
  }
}
