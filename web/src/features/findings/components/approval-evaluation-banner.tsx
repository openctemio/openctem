'use client'

/**
 * Why a finding request needs the approval it does, and who may give it
 * (the approval policy's evaluation, api/docs/rfcs/RFC-111-approval-policy.md).
 * Informational only: the API decides again when the request is made.
 */

import { AlertTriangle, ShieldCheck } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { reasonText, tierLabel, type ApprovalEvaluation } from '../lib/approval-policy'

/** Reason codes that describe the finding's risk (the "why"). */
const RISK_REASONS = new Set([
  'severity_critical',
  'severity_high',
  'priority_p0',
  'priority_p1',
  'kev',
  'epss_at_or_above_threshold',
  'exploit_validated',
  'crown_jewel',
  'internet_exposed',
  'requester_cannot_decide_alone',
  'requester_owns_asset',
  'group_decision',
])

/** Reason codes that say where the tier came from. */
const SOURCE_REASONS = new Set([
  'platform_floor',
  'platform_default',
  'organization_policy',
  'fp_level',
])

export function ApprovalEvaluationBanner({
  evaluation,
  className,
}: {
  evaluation: ApprovalEvaluation
  className?: string
}) {
  const { t } = useTranslation()
  const e = evaluation
  const reasons = e.reasons ?? []
  const why = reasons.filter((r) => RISK_REASONS.has(r)).map((r) => reasonText(t, r))
  const source = reasons.filter((r) => SOURCE_REASONS.has(r)).map((r) => reasonText(t, r))
  const fromPool = e.security_pool && !e.security_pool_fallback

  return (
    <div
      role="status"
      data-testid="approval-evaluation"
      className={cn('space-y-2 rounded-md border bg-muted/40 px-3 py-2 text-sm', className)}
    >
      <p className="flex items-center gap-2 font-medium">
        <ShieldCheck className="h-4 w-4 shrink-0 text-primary" aria-hidden />
        {t('findingApprovals.evaluation.headline', '{tier}: {count} approval(s) needed', {
          tier: tierLabel(t, e.tier),
          count: e.approvals_required,
        })}
      </p>
      {why.length > 0 && (
        <p>
          {t('findingApprovals.evaluation.why', 'Why: {reasons}.', { reasons: why.join(', ') })}
        </p>
      )}
      {source.length > 0 && (
        <p className="text-muted-foreground">
          {t('findingApprovals.evaluation.source', 'Set by {sources}.', {
            sources: source.join(', '),
          })}
        </p>
      )}
      <p>
        {e.tier === 'dual'
          ? t(
              'findingApprovals.evaluation.whoDual',
              'Two different people approve, at least one from the security pool. Eligible: {count} approvers, {pool} in the security pool.',
              { count: e.eligible_approvers, pool: e.eligible_security_pool }
            )
          : fromPool
            ? t(
                'findingApprovals.evaluation.whoPool',
                'An approver from the security pool decides. Eligible in the pool: {count}.',
                { count: e.eligible_security_pool }
              )
            : t(
                'findingApprovals.evaluation.whoAny',
                'Another approver decides. Eligible approvers: {count}.',
                { count: e.eligible_approvers }
              )}
      </p>
      {e.security_pool_fallback && (
        <p className="text-muted-foreground">
          {t(
            'findingApprovals.evaluation.fallback',
            'Nobody in the security pool is eligible, so any approver may decide.'
          )}
        </p>
      )}
      {e.step_up && (
        <p className="text-muted-foreground">
          {t(
            'findingApprovals.evaluation.stepUp',
            'Approvers confirm their identity before they decide.'
          )}
        </p>
      )}
      {e.kind === 'accepted' && !!e.max_acceptance_days && (
        <p className="text-muted-foreground">
          {t(
            'findingApprovals.evaluation.maxDays',
            'An acceptance of this finding lasts at most {days} days.',
            { days: e.max_acceptance_days }
          )}
        </p>
      )}
      {e.decide_within_days > 0 && (
        <p className="text-muted-foreground">
          {t(
            'findingApprovals.evaluation.decideWithin',
            'The request expires if nobody decides within {days} days.',
            { days: e.decide_within_days }
          )}
        </p>
      )}
      {!e.satisfiable && (
        <p
          className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-2 py-1.5 text-destructive"
          data-testid="approval-evaluation-unsatisfiable"
        >
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          {t(
            'findingApprovals.evaluation.unsatisfiable',
            'Your organization does not have enough eligible approvers for this request. It will wait until an administrator adds one or changes the security pool.'
          )}
        </p>
      )}
    </div>
  )
}
