'use client'

/**
 * "Remediation › Tasks › {task}" above a finding page that was opened from a
 * task (`?from=task:{id}`), linking back to the task. Without the permission
 * to read tasks, or when the task is gone, it renders nothing.
 */

import { useSearchParams } from 'next/navigation'
import { ChevronRight } from 'lucide-react'
import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { useTask } from '../api/use-remediation-hub'
import { taskFromParam } from '../lib/task-nav'

export function FromTaskCrumb() {
  const { t } = useTranslation()
  const taskId = taskFromParam(useSearchParams().get('from'))
  const { data: task } = useTask(taskId ?? undefined)
  if (!taskId || !task) return null
  return (
    <nav
      aria-label={t('remediationHub.crumb.label')}
      className="text-muted-foreground mb-3 flex flex-wrap items-center gap-1 text-sm"
    >
      <Link href="/remediation/tasks" className="hover:underline">
        {t('remediationHub.crumb.tasks')}
      </Link>
      <ChevronRight className="size-3.5 rtl:rotate-180" aria-hidden />
      <Link href={`/remediation/tasks/${taskId}`} className="hover:underline">
        {task.title}
      </Link>
      <ChevronRight className="size-3.5 rtl:rotate-180" aria-hidden />
      <span aria-current="page">{t('remediationHub.crumb.finding')}</span>
    </nav>
  )
}
