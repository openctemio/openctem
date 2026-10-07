'use client'

/**
 * Review by rule (RFC-054 §6.7): the review queue grouped into candidate
 * scope rules, a preview of what a rule action would change, and the action.
 *
 * A rule is a scope entry (accept) or a scope exclusion (reject), created
 * through the same routes as Scoping, so the same step-up, approvals, audit
 * and notifications apply; the API asks for re-authentication and the shared
 * client opens the dialog and retries. Everything is narrowed to the
 * caller's data scope by the server.
 */

import useSWR from 'swr'
import { get, post } from '@/lib/api/client'
import type { Schemas } from '@/lib/api/generated'
import { usePermissions, Permission } from '@/lib/permissions'

export type EASMRuleSuggestions =
  Schemas['github_com_openctemio_openctem_api_internal_app_easm.RuleSuggestions']
export type EASMRuleSuggestion =
  Schemas['github_com_openctemio_openctem_api_internal_app_easm.RuleSuggestion']
export type EASMRulePreview =
  Schemas['github_com_openctemio_openctem_api_internal_app_easm.RulePreview']

export type EASMRuleAction = 'accept_rule' | 'accept_selected' | 'reject_rule'

export interface EASMRuleRequest {
  action: EASMRuleAction
  target_type?: string
  pattern?: string
  asset_ids?: string[]
  reason?: string
}

export const SUGGESTIONS_URL = '/api/v1/easm/candidates/suggestions?states=needs_review,candidate'

/** GET /api/v1/easm/candidates/suggestions */
export function useEASMRuleSuggestions(enabled = true) {
  const { can } = usePermissions()
  const key = enabled && can(Permission.AssetsRead) ? SUGGESTIONS_URL : null
  const { data, error, isLoading, mutate } = useSWR<EASMRuleSuggestions>(key, get, {
    revalidateOnFocus: false,
    keepPreviousData: true,
  })
  return { suggestions: data, error, isLoading, mutate }
}

/** POST /api/v1/easm/candidates/rules/preview: changes nothing. */
export function previewRule(body: EASMRuleRequest) {
  return post<EASMRulePreview>('/api/v1/easm/candidates/rules/preview', body)
}

/** POST /api/v1/easm/candidates/rules: creates the entry / exclusion, decides items. */
export function applyRule(body: EASMRuleRequest) {
  return post<EASMRulePreview>('/api/v1/easm/candidates/rules', body)
}
