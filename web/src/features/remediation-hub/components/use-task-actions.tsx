'use client'

/**
 * The changes a person can make to one task, shared by the task page and the
 * task's quick-view sheet so both offer the same actions under the same gates:
 * Mark fixed (the one main action), and Put on hold / Resume and Cancel task in
 * the more menu. Every change needs findings remediation write on a task that
 * is not finished and whose findings are all in the person's data scope; Mark
 * fixed also needs the fix-apply permission. The API is the only authority.
 */

import { useCallback, useState } from 'react'
import { CheckCheck, PauseCircle, PlayCircle, XCircle } from 'lucide-react'
import { toast } from 'sonner'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { Button } from '@/components/ui/button'
import type { DetailMenuItem } from '@/features/shared/components/detail-sheet-layout'
import { TERMINAL_TASK_STATES, type MarkFixedResult, type RemediationTask } from '../api/types'
import { hubApi } from '../api/use-remediation-hub'
import { apiMessage } from './suggestions-inbox'
import { CancelTaskDialog, MarkFixedDialog } from './task-dialogs'

/** Whether the person may change this task (the page's and the sheet's one gate). */
export function useTaskWritable(task: RemediationTask | undefined) {
  const { hasPermission } = usePermissions()
  const canWrite = hasPermission(Permission.RemediationWrite)
  const writable =
    !!task && canWrite && !TERMINAL_TASK_STATES.has(task.state) && task.hidden_members === 0
  return { canWrite, writable, canFix: canWrite && hasPermission(Permission.FindingsFixApply) }
}

export function useTaskActions(
  task: RemediationTask | undefined,
  onChanged: () => Promise<unknown> | void
) {
  const { t } = useTranslation()
  const { writable, canFix } = useTaskWritable(task)
  const [busy, setBusy] = useState(false)
  const [fixOpen, setFixOpen] = useState(false)
  const [fixResult, setFixResult] = useState<MarkFixedResult | null>(null)
  const [cancelOpen, setCancelOpen] = useState(false)

  const openFix = useCallback(() => {
    setFixResult(null)
    setFixOpen(true)
  }, [])

  const markFixed = useCallback(
    async (note: string) => {
      if (!task) return
      setBusy(true)
      try {
        setFixResult(await hubApi.resolveTask(task.id, { version: task.version, note }))
        await onChanged()
      } catch (err) {
        toast.error(apiMessage(err, t('remediationHub.toast.failed')))
      } finally {
        setBusy(false)
      }
    },
    [onChanged, t, task]
  )

  /** true: put on hold, false: resume, null: cancel the task (with a note). */
  const setHold = useCallback(
    async (hold: boolean | null, note?: string) => {
      if (!task) return
      setBusy(true)
      try {
        await hubApi.updateTask(
          task.id,
          hold === null
            ? { version: task.version, cancel: true, note }
            : { version: task.version, hold }
        )
        setCancelOpen(false)
        await onChanged()
        toast.success(
          hold === null
            ? t('remediationHub.toast.canceled')
            : hold
              ? t('remediationHub.toast.held')
              : t('remediationHub.toast.resumed')
        )
      } catch (err) {
        toast.error(apiMessage(err, t('remediationHub.toast.failed')))
      } finally {
        setBusy(false)
      }
    },
    [onChanged, t, task]
  )

  const menu: DetailMenuItem[] =
    writable && task
      ? [
          task.state === 'on_hold'
            ? {
                label: t('remediationHub.detail.resume'),
                icon: PlayCircle,
                onSelect: () => void setHold(false),
              }
            : {
                label: t('remediationHub.detail.hold'),
                icon: PauseCircle,
                onSelect: () => void setHold(true),
              },
          {
            label: t('remediationHub.detail.cancel'),
            icon: XCircle,
            destructive: true,
            separatorBefore: true,
            onSelect: () => setCancelOpen(true),
          },
        ]
      : []

  const primary =
    writable && canFix ? (
      <Button onClick={openFix} aria-keyshortcuts="f">
        <CheckCheck className="size-4" aria-hidden />
        {t('remediationHub.detail.markFixed')}
      </Button>
    ) : null

  const dialogs = task ? (
    <>
      <MarkFixedDialog
        task={task}
        open={fixOpen}
        onOpenChange={setFixOpen}
        onConfirm={(note) => void markFixed(note)}
        busy={busy}
        result={fixResult}
      />
      <CancelTaskDialog
        open={cancelOpen}
        onOpenChange={setCancelOpen}
        onConfirm={(note) => void setHold(null, note)}
        busy={busy}
      />
    </>
  ) : null

  return {
    writable,
    canFix,
    busy,
    /** A dialog of these actions is open (keys wait). */
    dialogOpen: fixOpen || cancelOpen,
    openFix,
    menu,
    primary,
    dialogs,
  }
}
