'use client'

import type { ReactNode } from 'react'
import { Loader2 } from 'lucide-react'
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
  busy: boolean
}

function ActionButton({
  action,
  keyLabel,
  label,
  hint,
  onAction,
  disabled,
  primary,
  wide,
  busy,
}: {
  action: TriageAction
  keyLabel: string
  label: string
  hint?: string
  onAction: (a: TriageAction) => void
  disabled?: boolean
  primary?: boolean
  wide?: boolean
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
      className={cn('h-auto min-h-9 justify-start gap-2 py-1.5 text-start', wide && 'col-span-2')}
    >
      {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Kbd>{keyLabel}</Kbd>}
      <span className="flex min-w-0 flex-1 flex-col">
        <span className="truncate">{label}</span>
        {hint && (
          <span
            className={cn(
              'truncate text-[11px] font-normal',
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
 * The decision panel: one key per action, each a visible labelled button.
 * Decisions use the finding page's endpoints and checks; false positive and
 * risk acceptance stay requests the organization's policy decides.
 */
export function TriageDecisionPanel({
  state,
  onAction,
  assignControl,
}: {
  state: TriageDecisionState
  onAction: (a: TriageAction) => void
  /** The assignee picker (opened by `o`). */
  assignControl: ReactNode
}) {
  const { t } = useTranslation()
  const locked = !!state.lockedReason
  return (
    <aside
      role="region"
      aria-label={t('findings.triageMode.decision', 'Decision')}
      className="space-y-3 border-t bg-card p-4 lg:border-s lg:border-t-0"
      data-testid="triage-decision"
    >
      <p className="text-xs font-medium text-muted-foreground">
        {t('findings.triageMode.decideHint', 'Decide, one key per action')}
      </p>
      {state.lockedReason && (
        <p className="rounded-md border bg-muted/50 p-2 text-xs" role="note">
          {state.lockedReason}
        </p>
      )}
      <div className="grid grid-cols-2 gap-2">
        <ActionButton
          action="confirm"
          keyLabel="c"
          label={t('findings.triageMode.action.confirm', 'Confirm')}
          hint={t('findings.triageMode.action.confirmHint', 'A real issue to fix')}
          onAction={onAction}
          disabled={locked || !state.canConfirm || state.busy}
          busy={state.busy}
          primary
          wide
        />
        <ActionButton
          action="falsePositive"
          keyLabel="f"
          label={t('findings.triageMode.action.falsePositive', 'Request false positive')}
          hint={t('findings.triageMode.action.falsePositiveHint', 'Reason and note required')}
          onAction={onAction}
          disabled={locked || !state.canRequest || state.busy}
          wide
        />
        <ActionButton
          action="accept"
          keyLabel="a"
          label={t('findings.triageMode.action.accept', 'Request risk acceptance')}
          hint={t('findings.triageMode.action.acceptHint', 'Approval and an end date')}
          onAction={onAction}
          disabled={locked || !state.canRequest || state.busy}
          wide
        />
        <div className="col-span-2 flex items-center gap-2">
          <ActionButton
            action="assign"
            keyLabel="o"
            label={t('findings.triageMode.action.assign', 'Assign')}
            onAction={onAction}
            disabled={locked || !state.canAssign || state.busy}
          />
          <div className="min-w-0 flex-1" data-testid="triage-assign">
            {assignControl}
          </div>
        </div>
        <ActionButton
          action="skip"
          keyLabel="s"
          label={t('findings.triageMode.action.skip', 'Skip')}
          onAction={onAction}
          disabled={state.busy}
        />
        <ActionButton
          action="evidence"
          keyLabel="e"
          label={t('findings.triageMode.action.evidence', 'Evidence')}
          onAction={onAction}
        />
        <ActionButton
          action="openPage"
          keyLabel="Enter"
          label={t('findings.triageMode.action.openPage', 'Full page')}
          onAction={onAction}
        />
        <ActionButton
          action="help"
          keyLabel="?"
          label={t('findings.triageMode.action.help', 'All keys')}
          onAction={onAction}
        />
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
