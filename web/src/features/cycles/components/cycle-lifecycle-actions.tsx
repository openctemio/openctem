'use client'

import { useState } from 'react'
import { toast } from 'sonner'
import { CheckCircle, Eye, Play } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { confirmName } from '@/lib/confirm-name'
import { Can, Permission } from '@/lib/permissions'
import { ApiClientError, getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'
import { summarizeEvaluation } from '../charter-outcome'
import {
  COVERAGE_CHECK_FAILED,
  MIN_OVERRIDE_REASON,
  transitionCycle,
  type CloseOverride,
  type CycleTransition,
} from '../api'
import type { CtemCycle } from '../types'

// Label, title, body and toast of each step live in the catalog under
// scoping.lifecycle.<action>.{label,title,body,done}.
const ICONS: Record<CycleTransition, typeof Play> = {
  activate: Play,
  review: Eye,
  close: CheckCircle,
}

/** The one transition a cycle can take next, if any. */
export function nextTransition(status: CtemCycle['status']): CycleTransition | null {
  if (status === 'planning') return 'activate'
  if (status === 'active') return 'review'
  if (status === 'review') return 'close'
  return null
}

/**
 * The cycle's next lifecycle step as the page's primary action, behind a
 * confirmation (each step is irreversible). Transitions use their dedicated
 * endpoints, which snapshot scope (activate) and evaluate the charter (close).
 */
export function CycleLifecycleAction({
  cycle,
  onDone,
}: {
  cycle: CtemCycle
  onDone: (updated: CtemCycle | undefined, action: CycleTransition) => void
}) {
  const { t } = useTranslation()
  const action = nextTransition(cycle.status)
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  // Set when a close was refused because the coverage check could not run:
  // the person may close anyway with a reason, which the API audits.
  const [overriding, setOverriding] = useState(false)
  const [reason, setReason] = useState('')
  if (!action) return null
  const Icon = ICONS[action]
  const label = t(`scoping.lifecycle.${action}.label`, action)
  const done = t(`scoping.lifecycle.${action}.done`, action)

  const run = async (override?: CloseOverride) => {
    setConfirming(false)
    setOverriding(false)
    setBusy(true)
    try {
      const updated = await transitionCycle(cycle.id, action, override)
      const outcome =
        action === 'close' ? summarizeEvaluation(updated?.charter_evaluation, t) : null
      toast.success(
        outcome
          ? t('scoping.lifecycle.closeWithOutcome', '{done} {outcome}.', { done, outcome })
          : done
      )
      onDone(updated, action)
    } catch (err) {
      if (
        action === 'close' &&
        !override &&
        err instanceof ApiClientError &&
        err.code === COVERAGE_CHECK_FAILED
      ) {
        setReason('')
        setOverriding(true)
        return
      }
      toast.error(getErrorMessage(err, t('scoping.lifecycle.failed', 'Failed to update the cycle')))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Can permission={Permission.CTEMCyclesWrite}>
        <Button size="sm" onClick={() => setConfirming(true)} disabled={busy}>
          <Icon className="me-2 h-4 w-4" />
          {label}
        </Button>
      </Can>
      <ConfirmDialog
        open={confirming}
        onOpenChange={setConfirming}
        title={t(`scoping.lifecycle.${action}.title`, action)}
        desc={
          <>
            <span className="block font-medium text-foreground">
              {t('scoping.lifecycle.cycleName', 'Cycle: {name}', { name: cycle.name })}
            </span>
            <span className="mt-2 block">{t(`scoping.lifecycle.${action}.body`, action)}</span>
          </>
        }
        confirmText={label}
        // Activating freezes the scope and closing is final: type the cycle's name.
        typeToConfirm={action === 'review' ? undefined : confirmName(cycle.name, cycle.id)}
        destructive={action === 'close'}
        handleConfirm={() => run()}
      />
      <ConfirmDialog
        open={overriding}
        onOpenChange={setOverriding}
        title={t('scoping.lifecycle.override.title', 'Close without the coverage check?')}
        desc={t(
          'scoping.lifecycle.override.body',
          'The validation coverage check could not run, so the cycle was not closed. Try again later, or close it now with a reason. The reason is kept in the audit log.'
        )}
        confirmText={t('scoping.lifecycle.override.confirm', 'Close with this reason')}
        destructive
        disabled={reason.trim().length < MIN_OVERRIDE_REASON}
        isLoading={busy}
        handleConfirm={() => run({ override_coverage_check: true, override_reason: reason.trim() })}
      >
        <div className="space-y-2">
          <Label htmlFor="cycle-close-override-reason">
            {t('scoping.lifecycle.override.reason', 'Reason')}
          </Label>
          <Textarea
            id="cycle-close-override-reason"
            value={reason}
            maxLength={1000}
            onChange={(e) => setReason(e.target.value)}
            placeholder={t(
              'scoping.lifecycle.override.reasonPlaceholder',
              'Why the cycle can close without the check (at least {min} characters)',
              { min: MIN_OVERRIDE_REASON }
            )}
          />
        </div>
      </ConfirmDialog>
    </>
  )
}
