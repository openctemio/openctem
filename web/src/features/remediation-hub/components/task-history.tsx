'use client'

/**
 * The part of a task's page below the findings: the query it was created from
 * and its timeline. Both are read only when this block comes into view, so the
 * page's first load sends only what the first screen shows. The block sits at
 * the end of the page, so what fills it moves nothing the person is reading;
 * until then it holds the timeline's frame with a skeleton.
 */

import { useTranslation } from '@/context/i18n-provider'
import { useNearViewport } from '@/hooks/use-near-viewport'
import { Skeleton } from '@/components/ui/skeleton'
import { RelativeTime } from '@/features/shared/components/relative-time'
import type { RemediationTask } from '../api/types'
import { useTaskTimeline } from '../api/use-remediation-hub'
import { useOwnerLabels } from '../api/use-owner-names'
import { TaskQueryPanel } from './task-query-panel'

const ID = 'task-history'

export function TaskHistory({
  task,
  writable,
  onChanged,
}: {
  task: RemediationTask
  writable: boolean
  onChanged: () => void
}) {
  const { t } = useTranslation()
  const near = useNearViewport(ID, '0px')
  const { data: timeline } = useTaskTimeline(task.id, near)
  const events = timeline?.data ?? []
  const owners = useOwnerLabels(
    events.filter((e) => e.actor_type !== 'system').map((e) => e.actor_id),
    []
  )

  return (
    <div id={ID} className="space-y-4">
      {near && (
        <TaskQueryPanel
          taskId={task.id}
          taskVersion={task.version}
          writable={writable}
          onChanged={onChanged}
        />
      )}
      <section className="rounded-lg border p-4">
        <h2 className="mb-3 text-sm font-semibold">{t('remediationHub.detail.timeline')}</h2>
        {!timeline ? (
          <Skeleton className="h-16 w-full" />
        ) : events.length === 0 ? (
          <p className="text-muted-foreground text-sm">{t('remediationHub.detail.noEvents')}</p>
        ) : (
          <ol className="space-y-2">
            {events.map((e) => (
              <li key={e.id} className="flex flex-wrap items-baseline gap-2 text-sm">
                <RelativeTime
                  date={e.created_at}
                  className="text-muted-foreground w-28 shrink-0 text-xs"
                />
                <span>
                  {t(`remediationHub.event.${e.kind}`, e.kind, {
                    count: String(e.data.count ?? e.data.members ?? ''),
                    to: String(e.data.to ?? e.data.manual_state ?? ''),
                    title: String(
                      e.data.to_task_title ?? e.data.from_task_title ?? e.data.title ?? ''
                    ),
                    updated: String(e.data.updated ?? ''),
                  })}
                </span>
                <span className="text-muted-foreground text-xs">
                  {e.actor_type === 'system'
                    ? t('remediationHub.detail.platform')
                    : (owners.user(e.actor_id) ?? t('remediationHub.detail.someone'))}
                </span>
              </li>
            ))}
          </ol>
        )}
      </section>
    </div>
  )
}
