/**
 * Suppression / Exception types.
 *
 * Mirrors the API contract at `internal/infra/http/handler/suppression_handler.go`
 * (`SuppressionRuleResponse`, `CreateSuppressionRuleRequest`,
 * `UpdateSuppressionRuleRequest`) and the domain enums in
 * `pkg/domain/suppression/entity.go`.
 */

/** Approval lifecycle status of a suppression rule. */
export type SuppressionStatus = 'pending' | 'approved' | 'rejected' | 'expired'

/** Why a finding is being suppressed. */
export type SuppressionType = 'false_positive' | 'accepted_risk' | 'wont_fix'

/** A suppression rule as returned by `GET /api/v1/suppressions`. */
export interface SuppressionRule {
  id: string
  tenant_id: string
  name: string
  description?: string
  suppression_type: SuppressionType
  /** Tool rule ID pattern, e.g. "semgrep.sql-injection". */
  rule_id?: string
  /** Tool name, e.g. "semgrep", "betterleaks". */
  tool_name?: string
  /** File path glob, e.g. "tests/**". */
  path_pattern?: string
  asset_id?: string | null
  status: SuppressionStatus
  requested_by: string
  /** A requester that is not a user, e.g. "ci:gitlab:alice". */
  requested_by_actor?: string
  requested_at: string
  approved_by?: string | null
  approved_at?: string | null
  rejected_by?: string | null
  rejected_at?: string | null
  rejection_reason?: string
  expires_at?: string | null
  created_at: string
  updated_at: string
  /**
   * Set when the platform gave the rule an end it did not have (rules made
   * before an end was required); cleared when someone edits the rule.
   */
  review_flagged_at?: string | null
  /** Why the rule is flagged: `no_end_date`. */
  review_reason?: string
}

/** `POST /api/v1/suppressions/{id}/approve`: the rule plus what the approval closed. */
export interface ApproveSuppressionResponse extends SuppressionRule {
  /** Open findings the approval gave the rule's disposition. */
  applied_findings: number
  /** More matched than one approval closes; the rest stay open. */
  capped: boolean
}

/** `GET /api/v1/suppressions/{id}/preview`: what an approval would close now. */
export interface SuppressionPreview {
  /** Open findings of the organization the rule matches, at most `limit`. */
  matching_open_findings: number
  /** More than `limit` match; an approval closes `limit` of them. */
  capped: boolean
  limit: number
}

/** `GET /api/v1/suppressions` list envelope. */
export interface SuppressionListResponse {
  data: SuppressionRule[]
  total: number
}

/** Body for `POST /api/v1/suppressions`. */
export interface CreateSuppressionInput {
  name: string
  description?: string
  suppression_type: SuppressionType
  rule_id?: string
  tool_name?: string
  path_pattern?: string
  asset_id?: string | null
  /** RFC3339 timestamp; omit for a rule that never expires. */
  expires_at?: string | null
}

/** Body for `PUT /api/v1/suppressions/{id}`. */
export interface UpdateSuppressionInput {
  name?: string
  description?: string
  rule_id?: string
  tool_name?: string
  path_pattern?: string
  expires_at?: string | null
}

/** The console's translator (useTranslation().t). */
export type Translate = (
  key: string,
  fallback?: string,
  vars?: Record<string, string | number>
) => string

const plain: Translate = (_key, fallback = '') => fallback

/** English fallbacks of exceptions.type.<type>; render with suppressionTypeLabel. */
export const SUPPRESSION_TYPE_LABELS: Record<SuppressionType, string> = {
  false_positive: 'False Positive',
  accepted_risk: 'Accepted Risk',
  wont_fix: "Won't Fix",
}

/** English fallbacks of exceptions.status.<status>; render with suppressionStatusLabel. */
export const SUPPRESSION_STATUS_LABELS: Record<SuppressionStatus, string> = {
  pending: 'Pending',
  approved: 'Approved',
  rejected: 'Rejected',
  expired: 'Expired',
}

/**
 * Status → badge classes. Keyed by suppression status (NOT severity), so this is
 * outside the severity-color governance guard's scope.
 */
export const SUPPRESSION_STATUS_BADGE: Record<SuppressionStatus, string> = {
  pending: 'border-warning/40 bg-warning/10 text-warning',
  approved: 'border-success/30 bg-success/10 text-success',
  rejected: 'border-destructive/30 bg-destructive/10 text-destructive',
  expired: 'border-border bg-muted text-muted-foreground',
}

export const SUPPRESSION_TYPE_BADGE: Record<SuppressionType, string> = {
  false_positive: 'bg-blue-500/15 text-blue-600 dark:text-blue-400 border-blue-500/30', // palette-ok: suppression-type accent lookup, no semantic token
  accepted_risk: 'bg-purple-500/15 text-purple-600 dark:text-purple-400 border-purple-500/30', // palette-ok: suppression-type accent lookup
  wont_fix: 'bg-slate-500/15 text-slate-600 dark:text-slate-400 border-slate-500/30', // palette-ok: suppression-type accent lookup
}

/** Short human summary of a rule's matching criteria for table/scope cells. */
export function suppressionScopeSummary(rule: SuppressionRule, t: Translate = plain): string {
  const parts: string[] = []
  if (rule.tool_name) parts.push(rule.tool_name)
  if (rule.rule_id) parts.push(rule.rule_id)
  if (rule.path_pattern) parts.push(rule.path_pattern)
  if (rule.asset_id) parts.push(t('exceptions.scope.assetScoped', 'asset-scoped'))
  return parts.length ? parts.join(' · ') : t('exceptions.scope.any', 'Any finding')
}

export function suppressionTypeLabel(type: SuppressionType, t: Translate = plain): string {
  const fallback = SUPPRESSION_TYPE_LABELS[type]
  return fallback ? t(`exceptions.type.${type}`, fallback) : type
}

export function suppressionStatusLabel(status: SuppressionStatus, t: Translate = plain): string {
  const fallback = SUPPRESSION_STATUS_LABELS[status]
  return fallback ? t(`exceptions.status.${status}`, fallback) : status
}
