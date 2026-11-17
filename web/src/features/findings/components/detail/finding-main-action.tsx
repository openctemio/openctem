'use client'

/**
 * The finding page's one main action, chosen by the finding's state
 * (web/docs/finding-detail.md, "Header"):
 *
 *   duplicate of another finding        Open the original
 *   fix applied, a retest can run       Retest now
 *   in progress                         Mark fix applied
 *   otherwise                           Add to task
 *
 * Each keeps the gate it has elsewhere on the page: Retest now needs
 * findings:verify and the server's `can_retest` (the Proof of fix section's
 * rule), Mark fix applied needs the status permission, an unlocked finding and
 * the lifecycle's allowed move (asked when clicked, as the status menu does),
 * Add to task needs the task permission and the remediation module. When the
 * state's own action is not available the next one down applies.
 */

import { useState } from 'react'
import Link from '@/components/link'
import { CheckCircle2, ExternalLink, ListPlus, Loader2, RefreshCw } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useCanMutate } from '@/lib/permissions'
import { safeHref } from '@/lib/safe-href'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useModuleEnabled } from '@/features/integrations/api/use-tenant-modules'
import { AddFindingsToTaskDialog } from '@/features/remediation-hub/components/add-findings-to-task-dialog'
import { useFindingRetests, useRequestRetest } from '../../api/use-finding-retests'
import { useFindingRetestCheck } from '../../api/use-finding-retest-check'
import { fetchTransitions } from '../../api/triage-api'
import type { TransitionDecision } from '../../api/use-finding-transitions'
import { firstReason } from '../../lib/transition-reasons'
import { isTriageLocked } from '../../lib/finding-detail'
import type { FindingDetail, FindingStatus } from '../../types'

export type FindingMainActionKind = 'open-original' | 'retest' | 'mark-fixed' | 'add-to-task'

interface FindingMainActionProps {
  finding: FindingDetail
  status: FindingStatus
  /** The page's status move (the triage hook's): notes, approvals and undo stay its job. */
  onStatusMove?: (status: FindingStatus, move?: TransitionDecision) => void
}

export function FindingMainAction({ finding, status, onStatusMove }: FindingMainActionProps) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const canCreateTask = useCanMutate('POST /api/v1/remediation/tasks')
  const remediationEnabled = useModuleEnabled('remediation')
  const canAddToTask = canCreateTask && remediationEnabled
  const canMoveStatus =
    useCanMutate('PATCH /api/v1/findings/{id}/status') && !isTriageLocked(finding.source)
  const mayVerify = hasPermission('findings:verify')

  // Asked only in the state that uses it; the Proof of fix section reads the
  // same key, so on the Overview it is one request.
  const { data: retests } = useFindingRetests(
    status === 'fix_applied' && mayVerify ? finding.id : null
  )
  const { data: checkData } = useFindingRetestCheck(
    status === 'fix_applied' && mayVerify ? finding.id : null
  )
  const { trigger: requestRetest, isMutating: retesting } = useRequestRetest(finding.id)
  const retestRunning = retests?.data?.[0]?.status === 'pending'

  const [taskOpen, setTaskOpen] = useState(false)
  const [retestOpen, setRetestOpen] = useState(false)
  const [moving, setMoving] = useState(false)

  const originalHref = finding.duplicateOf
    ? safeHref(`/findings/${encodeURIComponent(finding.duplicateOf)}`)
    : undefined

  let kind: FindingMainActionKind | null = null
  if (originalHref) kind = 'open-original'
  else if (status === 'fix_applied' && mayVerify && retests?.can_retest === true) kind = 'retest'
  else if (status === 'in_progress' && canMoveStatus && onStatusMove) kind = 'mark-fixed'
  else if (canAddToTask) kind = 'add-to-task'

  const markFixed = async () => {
    if (!onStatusMove) return
    setMoving(true)
    try {
      // The lifecycle decides, as in the status menu: a blocked move says why.
      const moves = (await fetchTransitions(finding.id)).transitions.filter(
        (m) => m.to === 'fix_applied' && m.mode !== 'duplicate_picker'
      )
      const move =
        moves.find((m) => m.allowed && !m.to_sub_status_id) ?? moves.find((m) => m.allowed)
      if (!move) {
        toast.error(
          firstReason(t, moves[0]?.blocked) ??
            t(
              'findings.triageMode.moveNotAllowed',
              "Not possible from this finding's current status."
            )
        )
        return
      }
      onStatusMove('fix_applied', move)
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('findings.triage.statusFailed', 'Failed to update status'))
      )
    } finally {
      setMoving(false)
    }
  }

  const retestNow = async () => {
    setRetestOpen(false)
    try {
      await requestRetest(undefined)
      // The same words as the Proof of fix section's Retest button.
      const description =
        retests?.strategy?.kind === 'version_recheck'
          ? t(
              'findings.retestPanel.startedDescVersion',
              'A fingerprint scan is reading the software version again. The version it reads decides the result.'
            )
          : checkData?.check
            ? t(
                'findings.retestPanel.startedDescCheck',
                "The finding's retest check is running against its target."
              )
            : t(
                'findings.retestPanel.startedDesc',
                'The template that found this issue is running again against its target.'
              )
      toast.success(t('findings.retestPanel.started', 'Retest started'), { description })
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('findings.retestPanel.startFailed', 'Could not start the retest'))
      )
    }
  }

  return (
    <>
      {kind === 'open-original' && originalHref && (
        <Button asChild data-main-action={kind}>
          <Link href={originalHref}>
            <ExternalLink aria-hidden />
            {t('findings.header.openOriginal', 'Open the original')}
          </Link>
        </Button>
      )}
      {kind === 'retest' && (
        <Button
          onClick={() => setRetestOpen(true)}
          disabled={retesting || retestRunning}
          data-main-action={kind}
        >
          {retesting || retestRunning ? (
            <Loader2 className="animate-spin" aria-hidden />
          ) : (
            <RefreshCw aria-hidden />
          )}
          {t('findings.header.retestNow', 'Retest now')}
        </Button>
      )}
      {kind === 'mark-fixed' && (
        <Button onClick={() => void markFixed()} disabled={moving} data-main-action={kind}>
          {moving ? <Loader2 className="animate-spin" aria-hidden /> : <CheckCircle2 aria-hidden />}
          {t('findings.header.markFixApplied', 'Mark fix applied')}
        </Button>
      )}
      {kind === 'add-to-task' && (
        <Button onClick={() => setTaskOpen(true)} data-main-action={kind}>
          <ListPlus aria-hidden />
          {t('remediationClaim.add.addToTask', 'Add to task')}
        </Button>
      )}

      <ConfirmDialog
        open={retestOpen}
        onOpenChange={setRetestOpen}
        title={t('findings.retestPanel.confirmTitle', 'Retest this finding now?')}
        desc={t(
          'findings.retestPanel.confirmDesc',
          "This sends scan traffic to the finding's target now. The result is added to the retest history, and a verified fix can move the finding."
        )}
        confirmText={t('findings.retestPanel.confirmButton', 'Send retest')}
        handleConfirm={retestNow}
      />

      {canAddToTask && taskOpen && (
        <AddFindingsToTaskDialog
          open
          onOpenChange={(open) => {
            if (!open) setTaskOpen(false)
          }}
          findings={[{ id: finding.id, title: finding.title }]}
        />
      )}
    </>
  )
}
