'use client'

import { useState, type ReactNode } from 'react'
import { ChevronDown, ChevronLeft, ChevronRight, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
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
  className,
}: {
  action: TriageAction
  keyLabel: string
  label: string
  hint?: string
  onAction: (a: TriageAction) => void
  disabled?: boolean
  primary?: boolean
  busy?: boolean
  className?: string
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
        'h-auto min-h-control justify-start gap-2 py-1.5 text-start max-md:h-auto max-md:min-h-control-touch',
        className
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

function ConfirmButton({
  state,
  onAction,
  className,
}: {
  state: TriageDecisionState
  onAction: (a: TriageAction) => void
  className?: string
}) {
  const { t } = useTranslation()
  return (
    <ActionButton
      action="confirm"
      keyLabel="c"
      label={t('findings.triageMode.action.confirm', 'Confirm')}
      hint={t('findings.triageMode.action.confirmHint', 'A real issue to fix')}
      onAction={onAction}
      disabled={!!state.lockedReason || !state.canConfirm || state.busy}
      busy={state.busy}
      primary
      className={className}
    />
  )
}

/**
 * A phone's bottom bar: back to the previous finding, Skip, and Confirm, the
 * one main action, always on screen without scrolling. It sticks to the
 * bottom of the screen and ends the page. The other decisions are folded
 * under the finding; the session's counts are in the status line.
 */
export function TriagePhoneBar({
  state,
  onAction,
}: {
  state: TriageDecisionState
  onAction: (a: TriageAction) => void
}) {
  const { t } = useTranslation()
  return (
    <div
      role="region"
      aria-label={t('findings.triageMode.phoneBar', 'Confirm, skip or go back')}
      data-testid="triage-phone-bar"
      className="sticky bottom-0 z-20 -mx-4 flex items-center gap-2 border-t bg-background px-4 pt-3 pb-[max(0.75rem,env(safe-area-inset-bottom))]"
    >
      <Button
        type="button"
        variant="ghost"
        size="icon"
        onClick={() => onAction('prev')}
        disabled={!state.canPrev}
        aria-label={t('findings.triageMode.action.prev', 'Previous')}
        data-triage-action="prev"
      >
        <ChevronLeft className="rtl:rotate-180" aria-hidden />
      </Button>
      <Button
        type="button"
        variant="outline"
        onClick={() => onAction('skip')}
        disabled={state.busy}
        data-triage-action="skip"
      >
        {t('findings.triageMode.action.skip', 'Skip')}
      </Button>
      <Button
        type="button"
        className="min-w-0 flex-1"
        onClick={() => onAction('confirm')}
        disabled={!!state.lockedReason || !state.canConfirm || state.busy}
        data-triage-action="confirm"
      >
        {state.busy && <Loader2 className="animate-spin" aria-hidden />}
        <span className="truncate">
          {t('findings.triageMode.action.confirmPhone', 'Confirm, a real issue')}
        </span>
      </Button>
    </div>
  )
}

/**
 * The decisions on the shown finding, under it in the same card: one key
 * per action, each a visible labelled button, then Previous / Next.
 * Decisions use the finding page's endpoints and checks; false positive and
 * risk acceptance stay requests the organization's policy decides. Undo,
 * the queue, the keys and Exit are in the page header; Evidence and Full
 * page on the finding.
 *
 * On a phone Confirm, Skip and Previous are in the bar at the bottom of the
 * screen and the other decisions are folded under "Other decisions", so the
 * finding and its main action fit on one screen.
 */
export function TriageDecisionPanel({
  state,
  onAction,
  assignControl,
  phone = false,
  className,
}: {
  state: TriageDecisionState
  onAction: (a: TriageAction) => void
  /** The assignee picker (opened by `o`). */
  assignControl: ReactNode
  /** A phone: the bar holds the main actions; the rest is folded. */
  phone?: boolean
  className?: string
}) {
  const { t } = useTranslation()
  const [othersOpen, setOthersOpen] = useState(false)
  const locked = !!state.lockedReason
  const others = (
    <>
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
      <ActionButton
        action="assign"
        keyLabel="o"
        label={t('findings.triageMode.action.assign', 'Assign')}
        onAction={onAction}
        disabled={locked || !state.canAssign || state.busy}
      />
      {/* The picker the Assign key opens: its own cell, one height per row. */}
      <div className="min-w-0" data-testid="triage-assign">
        {assignControl}
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
    </>
  )
  const note = state.lockedReason && (
    <p className="rounded-md border bg-muted/50 p-2 text-xs" role="note">
      {state.lockedReason}
    </p>
  )

  if (phone) {
    return (
      <section
        role="region"
        aria-label={t('findings.triageMode.decision', 'Decision')}
        className={cn('space-y-3', className)}
        data-testid="triage-decision"
      >
        {note}
        <Collapsible className="rounded-lg border" open={othersOpen} onOpenChange={setOthersOpen}>
          <CollapsibleTrigger asChild>
            <button
              type="button"
              className="group flex w-full min-h-control-touch items-center justify-between gap-3 px-4 py-2.5 text-start focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
              data-testid="triage-other-decisions"
            >
              <span className="flex min-w-0 flex-col">
                <span className="text-sm font-medium">
                  {t('findings.triageMode.otherDecisions', 'Other decisions')}
                </span>
                <span className="text-xs text-muted-foreground">
                  {t(
                    'findings.triageMode.otherDecisionsHint',
                    'False positive, risk acceptance, assign, task, retest'
                  )}
                </span>
              </span>
              <ChevronDown
                className="size-4 shrink-0 transition-transform group-data-[state=open]:rotate-180"
                aria-hidden
              />
            </button>
          </CollapsibleTrigger>
          {/* Kept mounted while folded, so the assign key still finds its picker. */}
          <CollapsibleContent forceMount hidden={!othersOpen} className="grid gap-2 px-4 pb-4">
            {others}
          </CollapsibleContent>
        </Collapsible>
      </section>
    )
  }

  return (
    <section
      role="region"
      aria-label={t('findings.triageMode.decision', 'Decision')}
      className={cn('space-y-3', className)}
      data-testid="triage-decision"
    >
      <h2 className="sr-only">
        {t('findings.triageMode.decideHint', 'Decide, one key per action')}
      </h2>
      {note}
      <div className="grid gap-2 @xl/content:grid-cols-2 @5xl/content:grid-cols-4">
        <ConfirmButton state={state} onAction={onAction} />
        {others}
        <ActionButton
          action="skip"
          keyLabel="s"
          label={t('findings.triageMode.action.skip', 'Skip')}
          onAction={onAction}
          disabled={state.busy}
        />
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 border-t pt-3">
        <Button
          type="button"
          variant="ghost"
          onClick={() => onAction('prev')}
          disabled={!state.canPrev}
          aria-keyshortcuts="k"
          data-triage-action="prev"
        >
          <ChevronLeft className="rtl:rotate-180" aria-hidden />
          {t('findings.triageMode.action.prev', 'Previous')}
          <Kbd>k</Kbd>
        </Button>
        <Button
          type="button"
          variant="ghost"
          onClick={() => onAction('next')}
          disabled={!state.canNext}
          aria-keyshortcuts="j"
          data-triage-action="next"
        >
          {t('findings.triageMode.action.next', 'Next')}
          <Kbd>j</Kbd>
          <ChevronRight className="rtl:rotate-180" aria-hidden />
        </Button>
      </div>
      {/* A reading measure: on a wide card the note would run 1000 px on one line. */}
      <p className="max-w-prose text-xs leading-relaxed text-muted-foreground">
        {t(
          'findings.triageMode.policyNote',
          'Decisions use the same checks as the finding page: your permissions, your data scope, approvals and re-authentication. Re-authentication is asked once per window, not per finding.'
        )}
      </p>
    </section>
  )
}
