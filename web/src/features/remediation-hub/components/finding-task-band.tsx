'use client'

/**
 * On a finding: the remediation task(s) it belongs to, with the state and the
 * deadline, linking to the task. Shown only to people who can read
 * remediation; nothing shows when the finding is in no task or the
 * remediation module is off.
 */

import { useSettleSignal } from '@/features/shared/components/settle-group'
import { ClipboardCheck } from 'lucide-react'
import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import {
  SectionLoadError,
  isLoadFailure,
} from '@/features/findings/components/detail/section-load-error'
import { useTasks } from '../api/use-remediation-hub'
import { DeadlinePill, TaskStatePill } from './task-bits'

export function FindingTaskBand({
  findingId,
  className,
}: {
  findingId: string
  className?: string
}) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const canRead = hasPermission(Permission.RemediationRead)
  const { data, error, mutate, isLoading } = useTasks(
    { findingId, perPage: 3, sort: 'updated' },
    canRead && !!findingId
  )
  useSettleSignal(isLoading)
  const tasks = data?.data ?? []
  if (!canRead) return null
  if (error && isLoadFailure(error))
    return (
      <SectionLoadError
        title={t('findings.detail.section.task', 'the remediation task')}
        onRetry={() => void mutate()}
        className={className}
      />
    )
  if (error || tasks.length === 0) return null
  return (
    <div
      className={cn('bg-muted/40 flex flex-col gap-2 rounded-lg border p-3 text-sm', className)}
      data-testid="finding-task-band"
    >
      {tasks.map((task) => (
        <div key={task.id} className="flex flex-wrap items-center gap-2">
          <ClipboardCheck className="text-muted-foreground size-4 shrink-0" aria-hidden />
          <span className="text-muted-foreground">{t('remediationHub.band.tracked')}</span>
          <Link
            href={`/remediation/tasks/${task.id}`}
            className="min-w-0 font-medium break-words hover:underline"
          >
            {task.title}
          </Link>
          <TaskStatePill state={task.state} />
          <DeadlinePill task={task} />
        </div>
      ))}
    </div>
  )
}
