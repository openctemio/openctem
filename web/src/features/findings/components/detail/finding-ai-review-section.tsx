'use client'

import { useMemo } from 'react'
import { Bot } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import useSWR from 'swr'

import { AI_CONFIG_ENDPOINT } from '@/features/ai-triage/lib/ai-config'
import type { AIConfig } from '@/features/ai-triage/types'
import { useFindingAIRuns } from '@/features/ai-triage/api/use-ai-agents'
import { aiReviewOf, codeWords, type AIReviewState } from '@/features/ai-triage/lib/ai-review'
import { RelativeTime } from '@/features/shared'
import { AIBadge } from '@/features/shared/components/ai-badge'
import {
  DetailField,
  DetailFieldGrid,
  DetailSection,
} from '@/features/shared/components/detail-sheet'
import { toDisplayText } from '@/lib/untrusted-text'
import { usePermissionsSafe } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'

const STATE_FALLBACK: Record<AIReviewState, string> = {
  waiting: 'Waiting for AI',
  reviewing: 'AI reviewing',
  changed: 'Changed by AI',
  decide: 'Needs your decision',
  agrees: 'AI agrees',
  unsure: 'AI unsure',
  not_reviewed: 'Not reviewed',
}

const OUTCOME_FALLBACK: Record<string, string> = {
  applied: 'Applied',
  requested: 'Request filed for a person',
  commented: 'Written as a comment',
  skipped: 'Skipped',
}

const KIND_FALLBACK: Record<string, string> = {
  verdict: 'Verdict',
  severity: 'Severity',
  summary: 'Summary',
  remediation_steps: 'Remediation steps',
}

/**
 * The AI review beside a finding's status (api docs: architecture/ai-analysis.md):
 * the latest AI agent run, who ran it and where, and what became of each of
 * its suggestions. Everything shown is a code or a name; the AI agent's own
 * text is in its comments. The status itself stays a person's: this section
 * never blocks or replaces it. Shown only with ai_triage:read (no request is
 * sent without it) and when the finding has a run.
 */
export function FindingAIReviewSection({ findingId }: { findingId: string }) {
  const { t } = useTranslation()
  // Safe outside a permission provider (no permission: no request).
  const { hasPermission } = usePermissionsSafe()
  const canRead = hasPermission(Permission.AITriageRead)
  // Whether AI is on for the organization comes from the AI setup the
  // session bootstrap already put in the cache: read with no fetcher, so it
  // never sends a request. With AI off there is nothing to review and
  // nothing is asked.
  const { data: aiConfig } = useSWR<AIConfig>(AI_CONFIG_ENDPOINT, null)
  const aiOn = !!aiConfig && aiConfig.mode !== 'disabled' && aiConfig.reason !== 'not_enabled'
  const { data: runs } = useFindingAIRuns(findingId, canRead && aiOn)
  const review = useMemo(() => aiReviewOf(runs), [runs])
  if (!review) return null
  const { run } = review
  const accountable = run.accountable.map((o) => o.name).filter(Boolean)
  const onWorker = run.executor === 'tenant_worker' || run.executor === 'platform_worker'
  const model = [run.provider, run.model].filter(Boolean).map((v) => toDisplayText(v ?? '', 128))

  const reasonText = (code: string) => t(`findings.aiReview.reason.${code}`, codeWords(code))

  return (
    <DetailSection
      title={t('findings.aiReview.title', 'AI review')}
      icon={Bot}
      actions={
        <span className="flex items-center gap-2 text-xs text-muted-foreground">
          <Badge variant="outline" data-testid="ai-review-state" data-state={review.state}>
            {t(`findings.aiReview.state.${review.state}`, STATE_FALLBACK[review.state])}
          </Badge>
          <RelativeTime date={run.completed_at ?? run.created_at} />
        </span>
      }
    >
      <AIBadge source="ai_agent" name={run.ai_agent_name || undefined} accountable={accountable} />
      {review.state === 'not_reviewed' && review.reason && (
        <p className="text-sm text-muted-foreground">
          {t('findings.aiReview.notReviewedBecause', 'Not reviewed: {reason}', {
            reason: reasonText(review.reason),
          })}
        </p>
      )}
      <DetailFieldGrid className="sm:grid-cols-3">
        <DetailField label={t('findings.aiReview.runsOn', 'Runs on')}>
          {onWorker
            ? t('findings.aiReview.onWorker', 'An AI worker of your organization')
            : t('findings.aiReview.builtin', 'Built in')}
        </DetailField>
        <DetailField label={t('findings.aiReview.model', 'Model')}>
          {model.length > 0 ? (
            <span>
              {model.join(' / ')}
              {run.model_family && (
                <span className="text-muted-foreground">
                  {' '}
                  ({toDisplayText(run.model_family, 64)})
                </span>
              )}
            </span>
          ) : null}
        </DetailField>
        <DetailField label={t('findings.aiReview.trigger', 'Started by')}>
          {run.trigger === 'on_demand'
            ? t('findings.aiReview.byPerson', 'A person')
            : t('findings.aiReview.automatic', 'Automatically')}
        </DetailField>
      </DetailFieldGrid>
      {(run.action_log?.length ?? 0) > 0 && (
        <ul
          className="space-y-1 text-sm"
          aria-label={t('findings.aiReview.actions', 'What the AI agent did')}
        >
          {run.action_log!.map((a, i) => (
            <li key={`${a.kind}-${i}`} className="flex flex-wrap gap-x-2">
              <span className="font-medium">
                {t(`findings.aiReview.kind.${a.kind}`, KIND_FALLBACK[a.kind] ?? codeWords(a.kind))}
              </span>
              <span>
                {t(
                  `findings.aiReview.outcome.${a.outcome}`,
                  OUTCOME_FALLBACK[a.outcome] ?? codeWords(a.outcome)
                )}
              </span>
              {a.reason && <span className="text-muted-foreground">{reasonText(a.reason)}</span>}
            </li>
          ))}
        </ul>
      )}
    </DetailSection>
  )
}
