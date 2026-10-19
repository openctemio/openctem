'use client'

/** Triage actions and "create remediation task" of one alert. */

import { useMemo, useState } from 'react'
import { ListChecks, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { useTranslation } from '@/context/i18n-provider'
import { getErrorMessage } from '@/lib/api/error-handler'
import { Can, Permission } from '@/lib/permissions'
import { createRemediationTask, setAlertState, useRevalidateEmergingThreats } from '../api'
import {
  MAX_TASK_TITLE_LENGTH,
  splitTaskable,
  taskTitle,
  type EmergingThreatDetail,
  type NotAffectedReason,
  type TargetState,
} from '../types'
import { NotAffectedDialog } from './not-affected-dialog'

export function AlertActions({ alert }: { alert: EmergingThreatDetail }) {
  const { t } = useTranslation()
  const revalidate = useRevalidateEmergingThreats()
  const [busy, setBusy] = useState(false)
  const [naOpen, setNaOpen] = useState(false)
  const { state } = alert

  const move = async (
    target: TargetState,
    extra?: { reason: NotAffectedReason; note?: string }
  ) => {
    setBusy(true)
    try {
      await setAlertState(alert.id, target, extra)
      toast.success(t(`emergingThreats.toast.${target}`))
      setNaOpen(false)
      await revalidate()
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  const canAcknowledge = state === 'new'
  const canRemediate = state === 'new' || state === 'acknowledged'
  const canNotAffected = state === 'new' || state === 'acknowledged' || state === 'remediating'
  const canReopen = state !== 'new'

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Can permission={Permission.FindingsTriage}>
        {canAcknowledge && (
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() => void move('acknowledged')}
          >
            {t('emergingThreats.actions.acknowledge')}
          </Button>
        )}
        {canRemediate && (
          <Button
            size="sm"
            variant="outline"
            disabled={busy}
            onClick={() => void move('remediating')}
          >
            {t('emergingThreats.actions.remediating')}
          </Button>
        )}
        {canNotAffected && alert.can_suppress && (
          <Button size="sm" variant="outline" disabled={busy} onClick={() => setNaOpen(true)}>
            {t('emergingThreats.actions.notAffected')}
          </Button>
        )}
        {canReopen && (
          <Button size="sm" variant="outline" disabled={busy} onClick={() => void move('new')}>
            {t('emergingThreats.actions.reopen')}
          </Button>
        )}
      </Can>
      <Can permission={Permission.RemediationWrite}>
        <CreateTaskButton alert={alert} />
      </Can>
      <NotAffectedDialog
        open={naOpen}
        onOpenChange={setNaOpen}
        vulnId={alert.vuln_id}
        busy={busy}
        onConfirm={(reason, note) => void move('not_affected', { reason, note })}
      />
    </div>
  )
}

/** Why "Mark not affected" is missing, shown when the alert reaches beyond the caller's scope. */
export function OutOfScopeHint({ alert }: { alert: EmergingThreatDetail }) {
  const { t } = useTranslation()
  const eligibleState =
    alert.state === 'new' || alert.state === 'acknowledged' || alert.state === 'remediating'
  if (alert.can_suppress || !eligibleState) return null
  return (
    <Can permission={Permission.FindingsTriage}>
      <p className="text-xs text-muted-foreground">{t('emergingThreats.actions.outOfScopeHint')}</p>
    </Can>
  )
}

function CreateTaskButton({ alert }: { alert: EmergingThreatDetail }) {
  const { t } = useTranslation()
  const revalidate = useRevalidateEmergingThreats()
  const { eligible, alreadyInTask } = useMemo(() => splitTaskable(alert.assets), [alert.assets])
  const [open, setOpen] = useState(false)
  const [title, setTitle] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [createdId, setCreatedId] = useState<string | null>(null)

  const onOpenChange = (next: boolean) => {
    setOpen(next)
    if (next) {
      setTitle(taskTitle(alert.vuln_id, alert.title))
      setError(null)
      setCreatedId(null)
    }
  }

  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      const task = await createRemediationTask(
        title.trim(),
        eligible.map((a) => a.finding_id)
      )
      setCreatedId(task.id)
      await revalidate()
    } catch (err) {
      // 409: a finding joined another task since the page loaded.
      setError(getErrorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button
        size="sm"
        disabled={eligible.length === 0}
        title={eligible.length === 0 ? t('emergingThreats.task.nothingToAdd') : undefined}
        onClick={() => onOpenChange(true)}
      >
        <ListChecks className="me-2 h-4 w-4" aria-hidden />
        {t('emergingThreats.task.create')}
      </Button>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent size="md">
          <DialogHeader>
            <DialogTitle>{t('emergingThreats.task.title')}</DialogTitle>
            <DialogDescription>
              {t('emergingThreats.task.description', undefined, { n: eligible.length })}
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-3">
            {createdId ? (
              <p className="text-sm">
                {t('emergingThreats.task.created')}{' '}
                <Link href={`/remediation/tasks/${createdId}`} className="underline">
                  {t('emergingThreats.task.open')}
                </Link>
              </p>
            ) : (
              <>
                <div className="space-y-1">
                  <Label htmlFor="et-task-title">{t('emergingThreats.task.titleLabel')}</Label>
                  <Input
                    id="et-task-title"
                    value={title}
                    maxLength={MAX_TASK_TITLE_LENGTH}
                    onChange={(e) => setTitle(e.target.value)}
                  />
                </div>
                {alreadyInTask.length > 0 && (
                  <p className="text-sm text-muted-foreground">
                    {t('emergingThreats.task.alreadyInTask', undefined, {
                      n: alreadyInTask.length,
                    })}
                  </p>
                )}
                {error && (
                  <p role="alert" className="text-sm text-destructive">
                    {error}
                  </p>
                )}
              </>
            )}
          </DialogBody>
          <DialogFooter>
            <Button variant="outline" onClick={() => setOpen(false)}>
              {createdId ? t('emergingThreats.actions.close') : t('emergingThreats.actions.cancel')}
            </Button>
            {!createdId && (
              <Button
                disabled={busy || !title.trim() || eligible.length === 0}
                onClick={() => void submit()}
              >
                {busy && <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />}
                {t('emergingThreats.task.confirm', undefined, { n: eligible.length })}
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

/** The count line shown on the detail next to the actions. */
export function TaskCoverageNote({ alert }: { alert: EmergingThreatDetail }) {
  const { t } = useTranslation()
  const { alreadyInTask } = useMemo(() => splitTaskable(alert.assets), [alert.assets])
  if (alreadyInTask.length === 0) return null
  return (
    <p className="text-xs text-muted-foreground">
      {t('emergingThreats.task.alreadyInTask', undefined, { n: alreadyInTask.length })}
    </p>
  )
}
