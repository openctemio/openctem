'use client'

import type { ReactNode } from 'react'
import { ChevronLeft, ChevronRight, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { TriageAction } from '../../lib/triage-keys'
import { Kbd } from './kbd'

export interface TriageDecisionState {
  /** Why decisions are off for this finding (pentest workflow, no permission), if they are. */
  lockedReason?: string
  canConfirm: boolean
  canRequest: boolean
  canAssign: boolean
  /** Remediation module on and the task permission. */
  canTask: boolean
  /** findings:verify and a finding a tool can re-check. */
  canRetest: boolean
  busy: boolean
  /** Previous / next in the queue. */
  canPrev: boolean
  canNext: boolean
}

function ActionButton({
  action,
  keyLabel,
  label,
  hint,
  onAction,
  disabled,
  primary,
  busy,
}: {
  action: TriageAction
  keyLabel: string
  label: string
  hint?: string
  onAction: (a: TriageAction) => void
  disabled?: boolean
  primary?: boolean
  busy?: boolean
}) {
  return (
    <Button
      type="button"
      variant={primary ? 'default' : 'outline'}
      onClick={() => onAction(action)}
      disabled={disabled}
      aria-keyshortcuts={keyLabel === 'Esc' ? 'Escape' : keyLabel}
      data-triage-action={action}
      className={cn(
        'h-auto min-h-control justify-start gap-2 py-1.5 text-start max-md:h-auto max-md:min-h-control-touch'
      )}
    >
      {busy ? (
        <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
      ) : (
        <Kbd className="max-sm:hidden">{keyLabel}</Kbd>
      )}
      <span className="flex min-w-0 flex-1 flex-col">
        <span className="truncate">{label}</span>
        {hint && (
          <span
            className={cn(
              'truncate text-xs font-normal',
              primary ? 'opacity-80' : 'text-muted-foreground'
            )}
          >
            {hint}
          </span>
        )}
      </span>
    </Button>
  )
}

/**
 * The decision panel: one key per action, each a visible labelled button,
 * then Previous / Next. Decisions use the finding page's endpoints and
 * checks; false positive and risk acceptance stay requests the
 * organization's policy decides. Undo, the keys and Exit are in the page
 * header; Evidence and Full page on the finding.
 */
export function TriageDecisionPanel({
  state,
  onAction,
  assignControl,
  className,
}: {
  state: TriageDecisionState
  onAction: (a: TriageAction) => void
  /** The assignee picker (opened by `o`). */
  assignControl: ReactNode
  className?: string
}) {
  const { t } = useTranslation()
  const locked = !!state.lockedReason
  return (
    <aside
      role="region"
      aria-label={t('findings.triageMode.decision', 'Decision')}
      className={cn('space-y-3 rounded-lg border bg-card p-4', className)}
      data-testid="triage-decision"
    >
      <h2 className="text-sm font-medium">
        {t('findings.triageMode.decideHint', 'Decide, one key per action')}
      </h2>
      {state.lockedReason && (
        <p className="rounded-md border bg-muted/50 p-2 text-xs" role="note">
          {state.lockedReason}
        </p>
      )}
      <div className="grid gap-2">
        <ActionButton
          action="confirm"
          keyLabel="c"
          label={t('findings.triageMode.action.confirm', 'Confirm')}
          hint={t('findings.triageMode.action.confirmHint', 'A real issue to fix')}
          onAction={onAction}
          disabled={locked || !state.canConfirm || state.busy}
          busy={state.busy}
          primary
        />
        <ActionButton
          action="falsePositive"
          keyLabel="f"
          label={t('findings.triageMode.action.falsePositive', 'Request false positive')}
          hint={t('findings.triageMode.action.falsePositiveHint', 'Reason and note required')}
          onAction={onAction}
          disabled={locked || !state.canRequest || state.busy}
        />
        <ActionButton
          action="accept"
          keyLabel="a"
          label={t('findings.triageMode.action.accept', 'Request risk acceptance')}
          hint={t('findings.triageMode.action.acceptHint', 'Approval and an end date')}
          onAction={onAction}
          disabled={locked || !state.canRequest || state.busy}
        />
        {/* The Assign key and its picker, each on its own line: one height per row. */}
        <div className="grid gap-1.5">
          <ActionButton
            action="assign"
            keyLabel="o"
            label={t('findings.triageMode.action.assign', 'Assign')}
            onAction={onAction}
            disabled={locked || !state.canAssign || state.busy}
          />
          <div className="min-w-0" data-testid="triage-assign">
            {assignControl}
          </div>
        </div>
        <ActionButton
          action="task"
          keyLabel="m"
          label={t('findings.triageMode.action.task', 'Add to task')}
          onAction={onAction}
          disabled={locked || !state.canTask || state.busy}
        />
        <ActionButton
          action="retest"
          keyLabel="r"
          label={t('findings.triageMode.action.retest', 'Retest')}
          onAction={onAction}
          disabled={locked || !state.canRetest || state.busy}
        />
        <ActionButton
          action="skip"
          keyLabel="s"
          label={t('findings.triageMode.action.skip', 'Skip')}
          onAction={onAction}
          disabled={state.busy}
        />
      </div>
      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          variant="outline"
          onClick={() => onAction('prev')}
          disabled={!state.canPrev}
          aria-keyshortcuts="k"
          data-triage-action="prev"
        >
          <ChevronLeft className="rtl:rotate-180" aria-hidden />
          {t('findings.triageMode.action.prev', 'Previous')}
          <Kbd className="max-sm:hidden">k</Kbd>
        </Button>
        <Button
          type="button"
          variant="outline"
          onClick={() => onAction('next')}
          disabled={!state.canNext}
          aria-keyshortcuts="j"
          data-triage-action="next"
        >
          {t('findings.triageMode.action.next', 'Next')}
          <Kbd className="max-sm:hidden">j</Kbd>
          <ChevronRight className="rtl:rotate-180" aria-hidden />
        </Button>
      </div>
      <p className="text-xs leading-relaxed text-muted-foreground">
        {t(
          'findings.triageMode.policyNote',
          'Decisions use the same checks as the finding page: your permissions, your data scope, approvals and re-authentication. Re-authentication is asked once per window, not per finding.'
        )}
      </p>
    </aside>
  )
}
