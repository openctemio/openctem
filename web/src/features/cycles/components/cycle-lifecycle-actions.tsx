'use client'

import { useState } from 'react'
import { toast } from 'sonner'
import { CheckCircle, Eye, Play } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { Can, Permission } from '@/lib/permissions'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'
import { summarizeEvaluation } from '../charter-outcome'
import { transitionCycle, type CycleTransition } from '../api'
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
  if (!action) return null
  const Icon = ICONS[action]
  const label = t(`scoping.lifecycle.${action}.label`, action)
  const done = t(`scoping.lifecycle.${action}.done`, action)

  const run = async () => {
    setConfirming(false)
    setBusy(true)
    try {
      const updated = await transitionCycle(cycle.id, action)
      const outcome =
        action === 'close' ? summarizeEvaluation(updated?.charter_evaluation, t) : null
      toast.success(
        outcome
          ? t('scoping.lifecycle.closeWithOutcome', '{done} {outcome}.', { done, outcome })
          : done
      )
      onDone(updated, action)
    } catch (err) {
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
        handleConfirm={run}
      />
    </>
  )
}
