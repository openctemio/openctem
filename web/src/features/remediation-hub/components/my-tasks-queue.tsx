'use client'

/**
 * My Work "Tasks" tab: the open remediation tasks assigned to the caller or
 * to a group they belong to (`assignee=me`), earliest deadline first. The
 * full list and its views live on /remediation/tasks.
 */

import { useMemo } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import { ArrowRight } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { DataTable } from '@/features/shared'
import { ErrorState } from '@/features/shared/components/error-state'
import type { RemediationTask, TaskState } from '../api/types'
import { useTasks } from '../api/use-remediation-hub'
import { DeadlinePill, TaskProgress, TaskStatePill } from './task-bits'

export const MY_TASK_STATES: TaskState[] = ['open', 'in_progress', 'verifying', 'on_hold']

/** The queue shows the top of the list; "View all" opens Tasks on the "mine" view. */
const QUEUE_SIZE = 15

export function useMyTaskCount(enabled: boolean): number | undefined {
  const { data } = useTasks({ states: MY_TASK_STATES, mine: true, perPage: 1 }, enabled)
  return data?.total
}

export function MyTasksQueue() {
  const { t } = useTranslation()
  const router = useRouter()
  const { data, error, isLoading, mutate } = useTasks({
    states: MY_TASK_STATES,
    mine: true,
    sort: 'deadline',
    perPage: QUEUE_SIZE,
  })
  const rows = useMemo(() => data?.data ?? [], [data])
  const total = data?.total ?? 0

  const columns = useMemo<ColumnDef<RemediationTask>[]>(
    () => [
      {
        accessorKey: 'title',
        enableSorting: false,
        header: t('remediationHub.tasks.columns.task'),
        cell: ({ row }) => (
          <div className="max-w-[520px] min-w-0">
            <Link
              href={`/remediation/tasks/${row.original.id}`}
              className="truncate text-sm font-medium hover:underline"
              onClick={(e) => e.stopPropagation()}
            >
              {row.original.title}
            </Link>
            {row.original.action_title && row.original.action_title !== row.original.title && (
              <p className="text-muted-foreground truncate text-xs">{row.original.action_title}</p>
            )}
          </div>
        ),
      },
      {
        accessorKey: 'state',
        enableSorting: false,
        header: t('remediationHub.tasks.columns.state'),
        cell: ({ row }) => <TaskStatePill state={row.original.state} />,
      },
      {
        id: 'progress',
        enableSorting: false,
        header: t('remediationHub.tasks.columns.progress'),
        cell: ({ row }) => <TaskProgress task={row.original} className="w-32" />,
      },
      {
        id: 'deadline',
        enableSorting: false,
        header: t('remediationHub.tasks.columns.deadline'),
        cell: ({ row }) => <DeadlinePill task={row.original} />,
      },
    ],
    [t]
  )

  if (error) {
    return <ErrorState title={t('myWork.tasks.loadError')} onRetry={() => void mutate()} />
  }

  if (isLoading && !data) {
    return (
      <div className="space-y-2">
        <Skeleton className="h-9 w-full" />
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    )
  }

  return (
    <DataTable
      columns={columns}
      data={rows}
      showSearch={false}
      showColumnToggle={false}
      showPagination={false}
      pageSize={QUEUE_SIZE}
      getRowId={(task) => task.id}
      onRowClick={(task) => router.push(`/remediation/tasks/${task.id}`)}
      toolbarStart={
        <span className="text-muted-foreground text-sm">
          {total > rows.length
            ? t('myWork.tasks.topOf', undefined, {
                shown: rows.length,
                total: total.toLocaleString(),
              })
            : t('myWork.tasks.byDeadline')}
        </span>
      }
      toolbarEnd={
        <Button variant="outline" size="sm" asChild>
          <Link href="/remediation/tasks?view=mine">
            {t('myWork.tasks.viewAll')}
            <ArrowRight className="ms-2 h-4 w-4" />
          </Link>
        </Button>
      }
      emptyMessage={t('myWork.tasks.emptyTitle')}
      emptyDescription={t('myWork.tasks.emptyDescription')}
    />
  )
}
