'use client'

import { useState } from 'react'
import { ArrowDownRight, ArrowUpRight, Info, Plus } from 'lucide-react'
import { toast } from 'sonner'

import Link from '@/components/link'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissionsSafe } from '@/context/permission-provider'
import { PERSON_CLOSURE_REASONS, closureReasonLabel } from '@/features/findings/lib/closure'
import { AIBadge, aiSourceOfExecutor } from '@/features/shared/components/ai-badge'
import { DetailDisclosure } from '@/features/shared/components/detail-sheet'
import { TonePill, type PillTone } from '@/features/shared/components/tone-pill'
import { TruncatedText } from '@/features/shared/components/truncated-text'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { Permission } from '@/lib/permissions/constants'
import { toDisplayText } from '@/lib/untrusted-text'

import {
  AI_ERR_DECIDED,
  AI_ERR_UNDO_CONFLICT,
  applyAISuggestion,
  dismissAISuggestion,
  undoAISuggestion,
  type AIDirection,
  type AISuggestion,
  type AISuggestionState,
} from '../api/ai-governance-api'
import { AIModelText } from '../lib/ai-model-text'
import { isFalsePositiveVerdict, readPayload } from '../lib/suggestion-payload'

type T = ReturnType<typeof useTranslation>['t']
type Action = 'apply' | 'dismiss' | 'undo'

const STATE_TONE: Record<AISuggestionState, PillTone> = {
  open: 'info',
  needs_review: 'warning',
  pending_approval: 'warning',
  applied: 'success',
  auto_applied: 'success',
  dismissed: 'muted',
  superseded: 'muted',
  undone: 'muted',
  shadow: 'muted',
}

const STATE_FALLBACK: Record<AISuggestionState, string> = {
  open: 'Open',
  needs_review: 'Needs review',
  pending_approval: 'Waiting for approval',
  applied: 'Applied',
  auto_applied: 'Applied by policy',
  dismissed: 'Dismissed',
  superseded: 'Superseded',
  undone: 'Undone',
  shadow: 'Shadow',
}

const DIRECTION_FALLBACK: Record<AIDirection, string> = {
  additive: 'Adds information',
  raises_risk: 'Raises risk',
  lowers_risk: 'Lowers risk: needs approval',
}

const DIRECTION_ICON: Record<AIDirection, typeof Plus> = {
  additive: Plus,
  raises_risk: ArrowUpRight,
  lowers_risk: ArrowDownRight,
}

const VERDICT_FALLBACK: Record<string, string> = {
  true_positive: 'Real issue',
  likely_false_positive: 'Likely false positive',
  needs_info: 'Needs more information',
}

const REVIEW_FALLBACK: Record<string, string> = {
  unresolved_evidence: 'Cites evidence the run did not have',
  no_evidence: 'Cites no evidence',
  injection_suspected: 'The input looks like it tries to steer the AI',
  unknown_placeholder: 'Uses a placeholder the run did not issue',
  validator_coerced: 'The answer had to be corrected to fit the format',
}

export function kindLabel(t: T, kind: string): string {
  const fallback: Record<string, string> = {
    verdict: 'Verdict',
    severity: 'Severity',
    remediation_steps: 'Remediation steps',
    summary: 'Summary',
  }
  return t(`findings.aiSuggestions.kind.${kind}`, fallback[kind] ?? kind)
}

/** The user-facing text for a failed apply, dismiss or undo. */
export function decisionErrorMessage(t: T, err: unknown): string {
  if (err instanceof ApiClientError) {
    if (err.code === AI_ERR_UNDO_CONFLICT) {
      return t(
        'findings.aiSuggestions.error.undoConflict',
        'The field changed after the AI set it, so it was not restored. Change it by hand.'
      )
    }
    if (err.code === AI_ERR_DECIDED) {
      return t(
        'findings.aiSuggestions.error.decided',
        'Someone already decided this suggestion. The list is refreshed.'
      )
    }
    if (err.statusCode === 403) {
      return t(
        'findings.aiSuggestions.error.forbidden',
        'You do not have permission to make this change on this finding.'
      )
    }
  }
  return getErrorMessage(err)
}

export interface AISuggestionCardProps {
  suggestion: AISuggestion
  /** Called after a decision (and after a "decided" conflict) to refresh. */
  onChanged: () => void | Promise<unknown>
  /** Opens the "Why" drawer for the run. */
  onWhy: (runId: string) => void
}

/**
 * One AI suggestion on a finding: the shared AI badge, what it proposes (as
 * plain text), the direction the platform computed, confidence, evidence and
 * state, with Apply, Dismiss and Undo behind a confirmation.
 */
export function AISuggestionCard({ suggestion: s, onChanged, onWhy }: AISuggestionCardProps) {
  const { t } = useTranslation()
  const { hasPermission: can } = usePermissionsSafe()
  const [pending, setPending] = useState<Action | null>(null)
  const [closureReason, setClosureReason] = useState('')

  const payload = readPayload(s)
  const needsClosure = isFalsePositiveVerdict(s)
  const canAct =
    s.kind === 'severity' ? can(Permission.FindingsSeverity) : can(Permission.FindingsWrite)
  const decidable = s.state === 'open' || s.state === 'needs_review'
  const undoable = s.state === 'applied' || s.state === 'auto_applied'
  const DirIcon = DIRECTION_ICON[s.direction] ?? Info

  const run = async (action: Action) => {
    try {
      if (action === 'apply') {
        const res = await applyAISuggestion(s.id, needsClosure ? closureReason : undefined)
        toast.success(
          res.pending_approval
            ? t(
                'findings.aiSuggestions.toast.requested',
                'Approval requested. Another person decides it.'
              )
            : t('findings.aiSuggestions.toast.applied', 'Suggestion applied')
        )
      } else if (action === 'dismiss') {
        await dismissAISuggestion(s.id)
        toast.success(t('findings.aiSuggestions.toast.dismissed', 'Suggestion dismissed'))
      } else {
        await undoAISuggestion(s.id)
        toast.success(t('findings.aiSuggestions.toast.undone', 'Change undone'))
      }
      setPending(null)
      setClosureReason('')
      await onChanged()
    } catch (err) {
      toast.error(decisionErrorMessage(t, err))
      if (err instanceof ApiClientError && err.code === AI_ERR_DECIDED) {
        setPending(null)
        await onChanged()
      }
    }
  }

  const confirmTitle =
    pending === 'apply'
      ? t('findings.aiSuggestions.confirm.applyTitle', 'Apply this AI suggestion?')
      : pending === 'dismiss'
        ? t('findings.aiSuggestions.confirm.dismissTitle', 'Dismiss this AI suggestion?')
        : t('findings.aiSuggestions.confirm.undoTitle', 'Undo this change?')
  const confirmDesc =
    pending === 'apply'
      ? s.direction === 'lowers_risk'
        ? t(
            'findings.aiSuggestions.confirm.applyLowers',
            'This lowers the risk shown for the finding, so it opens an approval request. You become the requester and someone else decides it.'
          )
        : s.kind === 'severity'
          ? t(
              'findings.aiSuggestions.confirm.applySeverity',
              'The finding’s severity changes to the suggested value. Severity rules still apply.'
            )
          : t(
              'findings.aiSuggestions.confirm.applyAdditive',
              'The suggestion is added to the finding’s record. You can undo it later.'
            )
      : pending === 'dismiss'
        ? t(
            'findings.aiSuggestions.confirm.dismissDesc',
            'Nothing on the finding changes. Dismissals count against the AI’s quality score.'
          )
        : t(
            'findings.aiSuggestions.confirm.undoDesc',
            'The previous value is restored if nobody changed it since.'
          )

  return (
    <article
      className="space-y-3 rounded-lg border bg-card p-3"
      data-testid="ai-suggestion-card"
      data-state={s.state}
      aria-label={kindLabel(t, s.kind)}
    >
      <div className="flex flex-wrap items-center gap-2">
        <AIBadge source={aiSourceOfExecutor(s.run?.executor)} />
        <TonePill
          tone={STATE_TONE[s.state] ?? 'muted'}
          state={s.state}
          label={t(`findings.aiSuggestions.state.${s.state}`, STATE_FALLBACK[s.state] ?? s.state)}
        />
        <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
          <DirIcon className="h-3.5 w-3.5" aria-hidden />
          {t(
            `findings.aiSuggestions.direction.${s.direction}`,
            DIRECTION_FALLBACK[s.direction] ?? s.direction
          )}
        </span>
        {typeof s.confidence === 'number' && (
          <span className="text-xs tabular-nums text-muted-foreground">
            {t('findings.aiSuggestions.confidence', 'Confidence {value}%', {
              value: Math.round(s.confidence * 100),
            })}
          </span>
        )}
      </div>

      <SuggestionBody s={s} payload={payload} t={t} />

      {s.review_reasons.length > 0 && (
        <div className="space-y-1 text-xs">
          <p className="font-medium">
            {t('findings.aiSuggestions.reviewTitle', 'Check this before you apply it')}
          </p>
          <ul className="list-disc space-y-0.5 ps-5 text-muted-foreground">
            {s.review_reasons.map((r) => (
              <li key={r}>{t(`findings.aiSuggestions.review.${r}`, REVIEW_FALLBACK[r] ?? r)}</li>
            ))}
          </ul>
        </div>
      )}

      {s.evidence.length > 0 && (
        <DetailDisclosure
          summary={t('findings.aiSuggestions.evidence', 'Evidence ({count})', {
            count: s.evidence.length,
          })}
        >
          <ul className="space-y-2">
            {s.evidence.map((e, i) => (
              <li key={`${e.ref}-${i}`} className="space-y-1">
                <TruncatedText
                  value={e.ref}
                  className="block max-w-full font-mono text-xs"
                  label={t('findings.aiSuggestions.evidenceRef', 'Evidence reference')}
                />
                {e.quote && <AIModelText text={e.quote} collapsed={300} />}
              </li>
            ))}
          </ul>
        </DetailDisclosure>
      )}

      <div className="flex flex-wrap items-center gap-2">
        {decidable && canAct && (
          <>
            <Button size="sm" onClick={() => setPending('apply')}>
              {s.direction === 'lowers_risk'
                ? t('findings.aiSuggestions.requestApproval', 'Request approval')
                : t('findings.aiSuggestions.apply', 'Apply')}
            </Button>
            <Button size="sm" variant="outline" onClick={() => setPending('dismiss')}>
              {t('findings.aiSuggestions.dismiss', 'Dismiss')}
            </Button>
          </>
        )}
        {undoable && canAct && (
          <Button size="sm" variant="outline" onClick={() => setPending('undo')}>
            {t('findings.aiSuggestions.undo', 'Undo')}
          </Button>
        )}
        {s.state === 'pending_approval' && (
          <Button size="sm" variant="link" className="px-0" asChild>
            <Link href="/findings/approvals">
              {t('findings.aiSuggestions.viewApproval', 'View the approval request')}
            </Link>
          </Button>
        )}
        <Button size="sm" variant="ghost" onClick={() => onWhy(s.run_id)}>
          {t('findings.aiSuggestions.why', 'Why?')}
        </Button>
      </div>

      <ConfirmDialog
        open={pending !== null}
        onOpenChange={(open) => {
          if (!open) {
            setPending(null)
            setClosureReason('')
          }
        }}
        title={confirmTitle}
        desc={confirmDesc}
        destructive={pending === 'dismiss'}
        disabled={pending === 'apply' && needsClosure && closureReason === ''}
        confirmText={
          pending === 'apply'
            ? s.direction === 'lowers_risk'
              ? t('findings.aiSuggestions.requestApproval', 'Request approval')
              : t('findings.aiSuggestions.apply', 'Apply')
            : pending === 'dismiss'
              ? t('findings.aiSuggestions.dismiss', 'Dismiss')
              : t('findings.aiSuggestions.undo', 'Undo')
        }
        handleConfirm={() => (pending ? run(pending) : undefined)}
      >
        {pending === 'apply' && needsClosure && (
          <div className="space-y-1.5">
            <Label htmlFor={`ai-closure-${s.id}`}>
              {t('findings.aiSuggestions.closureReason', 'Why is it a false positive?')}
            </Label>
            <Select value={closureReason} onValueChange={setClosureReason}>
              <SelectTrigger id={`ai-closure-${s.id}`}>
                <SelectValue
                  placeholder={t('findings.aiSuggestions.closurePlaceholder', 'Choose a reason')}
                />
              </SelectTrigger>
              <SelectContent>
                {(PERSON_CLOSURE_REASONS.false_positive ?? []).map((r) => (
                  <SelectItem key={r} value={r}>
                    {closureReasonLabel(t, r)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        )}
      </ConfirmDialog>
    </article>
  )
}

function SuggestionBody({
  s,
  payload,
  t,
}: {
  s: AISuggestion
  payload: ReturnType<typeof readPayload>
  t: T
}) {
  switch (s.kind) {
    case 'verdict':
      return (
        <div className="space-y-1">
          <p className="text-sm font-medium">
            {payload.verdict
              ? t(
                  `findings.aiSuggestions.verdict.${payload.verdict}`,
                  VERDICT_FALLBACK[payload.verdict] ?? payload.verdict
                )
              : kindLabel(t, s.kind)}
          </p>
          {payload.reason && <AIModelText text={payload.reason} />}
        </div>
      )
    case 'severity':
      return (
        <div className="space-y-1">
          <p className="flex items-center gap-2 text-sm font-medium">
            {t('findings.aiSuggestions.suggestedSeverity', 'Suggested severity')}
            {payload.severity && <SeverityBadge severity={payload.severity} />}
          </p>
          {payload.reason && <AIModelText text={payload.reason} />}
        </div>
      )
    case 'remediation_steps':
      return (
        <ol className="list-decimal space-y-1 ps-5">
          {payload.steps.map((step, i) => (
            <li key={i}>
              <AIModelText text={step.description} collapsed={400} />
              {step.effort && (
                <span className="text-xs text-muted-foreground">
                  {t('findings.aiSuggestions.effort', 'Effort: {effort}', {
                    effort: t(
                      `findings.aiSuggestions.effortLevel.${step.effort}`,
                      toDisplayText(step.effort, 40)
                    ),
                  })}
                </span>
              )}
            </li>
          ))}
        </ol>
      )
    default:
      return payload.text ? <AIModelText text={payload.text} /> : null
  }
}
