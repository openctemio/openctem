'use client'

/**
 * Remediation tasks as a table or a board. Saved views (all open, mine, due
 * soon, verifying, closed) are presets of the server filters; the table pages
 * on the server. On the board only the states a person sets move by drag
 * (put on hold, resume); every other state follows the findings.
 */

import { useCallback, useMemo, useState } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import type { ColumnDef } from '@tanstack/react-table'
import {
  DndContext,
  type DragEndEvent,
  PointerSensor,
  KeyboardSensor,
  useDraggable,
  useDroppable,
  useSensor,
  useSensors,
} from '@dnd-kit/core'
import { ClipboardList, LayoutGrid, SquareCode, Table2 } from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { useOpenForm } from '@/hooks/use-open-form'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { DataTable, FilterSelect, ListToolbar, PageStack, ViewSwitcher } from '@/features/shared'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { cn } from '@/lib/utils'
import type { RemediationTask, TaskState } from '../api/types'
import {
  type TaskListFilters,
  hubApi,
  useRevalidateHub,
  useTasks,
} from '../api/use-remediation-hub'
import { useOwnerNames } from '../api/use-owner-names'
import { CreateTaskFromQueryDialog } from './create-task-from-query-dialog'
import { apiMessage } from './suggestions-inbox'
import { DeadlinePill, TaskProgress, TaskStatePill } from './task-bits'
import { VIEW_FILTERS, type TaskView } from './task-views'
import { useSearchQuery } from '@/hooks/use-search-query'

export type { TaskView }

const BOARD_COLUMNS: TaskState[] = ['open', 'in_progress', 'verifying', 'on_hold', 'done']

export function TasksView({ defaultView = 'open' }: { defaultView?: TaskView }) {
  const { t } = useTranslation()
  const router = useRouter()
  const params = useSearchParams()
  const { hasPermission } = usePermissions()
  const canWrite = hasPermission(Permission.RemediationWrite)
  // Creating a task from a query runs the query: findings read too.
  const canQueryCreate = canWrite && hasPermission(Permission.FindingsRead)
  const [queryOpen, setQueryOpen] = useState(false)
  const openTaskForm = useCallback(() => setQueryOpen(true), [])
  useOpenForm('task', canQueryCreate, openTaskForm)
  // A card dropped on On hold or back to work waits here for a confirmation.
  const [pendingHold, setPendingHold] = useState<{
    task: RemediationTask
    hold: boolean
  } | null>(null)
  const owners = useOwnerNames()
  const revalidate = useRevalidateHub()
  const view = (params.get('view') as TaskView) || defaultView
  const layout = params.get('layout') === 'board' ? 'board' : 'table'
  const [search, setSearch] = useState('')
  const searchTerm = useSearchQuery(search).term
  const [sort, setSort] = useState<TaskListFilters['sort']>('deadline')
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: 25 })
  const filters: TaskListFilters = {
    ...(VIEW_FILTERS[view] ?? VIEW_FILTERS.open),
    search: searchTerm,
    sort,
    page: layout === 'board' ? 1 : pagination.pageIndex + 1,
    perPage: layout === 'board' ? 100 : pagination.pageSize,
  }
  const { data, error, isLoading, mutate } = useTasks(filters)
  const tasks = useMemo(() => data?.data ?? [], [data])

  const setParam = useCallback(
    (key: string, value: string) => {
      const next = new URLSearchParams(params.toString())
      next.set(key, value)
      router.replace(`?${next.toString()}`)
      setPagination((p) => ({ ...p, pageIndex: 0 }))
    },
    [params, router]
  )

  const ownerOf = useCallback(
    (task: RemediationTask) =>
      [owners.user(task.assignee_user_id), owners.group(task.assignee_group_id)]
        .filter(Boolean)
        .join(' · ') || t('remediationHub.owner.unassigned'),
    [owners, t]
  )

  const columns = useMemo<ColumnDef<RemediationTask>[]>(
    () => [
      {
        accessorKey: 'title',
        header: t('remediationHub.tasks.columns.task'),
        cell: ({ row }) => (
          <div className="min-w-0">
            <Link
              href={`/remediation/tasks/${row.original.id}`}
              className="font-medium hover:underline"
            >
              {row.original.title}
            </Link>
            <div className="text-muted-foreground truncate text-xs">
              {row.original.action_title}
            </div>
          </div>
        ),
      },
      {
        accessorKey: 'state',
        header: t('remediationHub.tasks.columns.state'),
        cell: ({ row }) => <TaskStatePill state={row.original.state} />,
      },
      {
        id: 'owner',
        header: t('remediationHub.tasks.columns.owner'),
        cell: ({ row }) => <span className="text-sm">{ownerOf(row.original)}</span>,
      },
      {
        id: 'progress',
        header: t('remediationHub.tasks.columns.progress'),
        cell: ({ row }) => (
          <div className="w-32">
            <TaskProgress task={row.original} />
            <div className="text-muted-foreground mt-1 text-xs">
              {t('remediationHub.tasks.verifiedOf', undefined, {
                verified: row.original.counts.verified,
                total: row.original.counts.total,
              })}
            </div>
          </div>
        ),
      },
      {
        accessorKey: 'deadline',
        header: t('remediationHub.tasks.columns.deadline'),
        cell: ({ row }) => <DeadlinePill task={row.original} />,
      },
      {
        id: 'risk',
        header: t('remediationHub.tasks.columns.risk'),
        cell: ({ row }) => (
          <span className="font-mono text-sm" title={t('remediationHub.risk.explain')}>
            {row.original.counts.risk_points}
          </span>
        ),
      },
    ],
    [ownerOf, t]
  )

  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 6 } }),
    useSensor(KeyboardSensor)
  )
  const onDragEnd = useCallback(
    async (e: DragEndEvent) => {
      const task = tasks.find((x) => x.id === e.active.id)
      const to = e.over?.id as TaskState | undefined
      if (!task || !to || to === task.state) return
      // Only the person-set state moves: put on hold, or resume from hold.
      const hold =
        to === 'on_hold'
          ? true
          : task.state === 'on_hold' && (to === 'open' || to === 'in_progress')
            ? false
            : undefined
      if (hold === undefined) {
        toast.info(t('remediationHub.tasks.derivedOnly'))
        return
      }
      setPendingHold({ task, hold })
    },
    [t, tasks]
  )

  const applyHold = useCallback(async () => {
    if (!pendingHold) return
    const { task, hold } = pendingHold
    try {
      await hubApi.updateTask(task.id, { version: task.version, hold })
      toast.success(hold ? t('remediationHub.toast.held') : t('remediationHub.toast.resumed'))
      setPendingHold(null)
      await Promise.all([mutate(), revalidate()])
    } catch (err) {
      setPendingHold(null)
      toast.error(apiMessage(err, t('remediationHub.toast.failed')))
    }
  }, [mutate, revalidate, pendingHold, t])

  const viewLabels: TaskView[] = ['open', 'mine', 'verifying', 'on_hold', 'closed', 'all']

  return (
    <PageStack>
      {/* One toolbar row: which tasks (a filter token, not a second row of
          tabs under the section tabs), search; then sort, the table/board
          view switch and the create action at the end. */}
      <ListToolbar
        search={{
          value: search,
          onChange: setSearch,
          placeholder: t('remediationHub.tasks.search'),
        }}
        start={
          <>
            <FilterSelect<TaskView>
              label={t('remediationHub.tasks.showLabel', 'Show')}
              value={view}
              clearable={false}
              options={viewLabels.map((v) => ({
                value: v,
                label: t(`remediationHub.tasks.view.${v}`),
              }))}
              onChange={(v) => setParam('view', v || 'open')}
            />
          </>
        }
        end={
          <>
            <Select value={sort} onValueChange={(v) => setSort(v as TaskListFilters['sort'])}>
              <SelectTrigger className="h-9 w-40" aria-label={t('remediationHub.tasks.sort')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(['deadline', 'risk', 'updated', 'created'] as const).map((s) => (
                  <SelectItem key={s} value={s}>
                    {t(`remediationHub.tasks.sortBy.${s}`)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <ViewSwitcher
              options={[
                { value: 'table', label: t('remediationHub.tasks.table'), icon: Table2 },
                { value: 'board', label: t('remediationHub.tasks.board'), icon: LayoutGrid },
              ]}
              value={layout === 'board' ? 'board' : 'table'}
              onChange={(v) => setParam('layout', v)}
            />
            {canQueryCreate && (
              <Button size="sm" className="h-9" onClick={() => setQueryOpen(true)}>
                <SquareCode className="size-4" aria-hidden />
                {t('remediationQuery.create.entry')}
              </Button>
            )}
          </>
        }
      />
      {canQueryCreate && <CreateTaskFromQueryDialog open={queryOpen} onOpenChange={setQueryOpen} />}

      {error ? (
        <ErrorState
          title={t('remediationHub.tasks.loadError')}
          error={error}
          onRetry={() => void mutate()}
        />
      ) : !isLoading && tasks.length === 0 ? (
        <EmptyState
          icon={ClipboardList}
          title={t('remediationHub.tasks.emptyTitle')}
          description={t('remediationHub.tasks.emptyDescription')}
          action={
            <Button asChild variant="outline">
              <Link href="/remediation/suggestions">
                {t('remediationHub.tasks.reviewSuggestions')}
              </Link>
            </Button>
          }
          card
        />
      ) : layout === 'table' ? (
        <DataTable
          columns={columns}
          data={tasks}
          showSearch={false}
          manualPagination
          rowCount={data?.total ?? 0}
          pageCount={data ? Math.max(1, Math.ceil(data.total / pagination.pageSize)) : 1}
          pagination={pagination}
          onPaginationChange={setPagination}
          getRowId={(r) => r.id}
          onRowClick={(r) => router.push(`/remediation/tasks/${r.id}`)}
          emptyMessage={t('remediationHub.tasks.emptyTitle')}
          mobileRow={(r) => <TaskCard task={r} owner={ownerOf(r)} />}
        />
      ) : (
        <DndContext sensors={sensors} onDragEnd={(e) => void onDragEnd(e)}>
          <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-5" data-testid="task-board">
            {BOARD_COLUMNS.map((col) => (
              <BoardColumn
                key={col}
                state={col}
                tasks={tasks.filter((x) =>
                  col === 'done'
                    ? x.state === 'done' || x.state === 'closed_unverified'
                    : x.state === col
                )}
                ownerOf={ownerOf}
                canDrag={canWrite}
              />
            ))}
          </div>
        </DndContext>
      )}
      <ConfirmDialog
        open={pendingHold !== null}
        onOpenChange={(open) => {
          if (!open) setPendingHold(null)
        }}
        title={
          pendingHold?.hold
            ? t('remediationHub.tasks.holdTitle', 'Put "{title}" on hold?', {
                title: pendingHold.task.title,
              })
            : t('remediationHub.tasks.resumeTitle', 'Resume "{title}"?', {
                title: pendingHold?.task.title ?? '',
              })
        }
        desc={
          pendingHold?.hold
            ? t(
                'remediationHub.tasks.holdDesc',
                'The task shows as On hold until someone resumes it. Its findings stay in it.'
              )
            : t(
                'remediationHub.tasks.resumeDesc',
                'The task leaves On hold and its state follows its findings again.'
              )
        }
        confirmText={
          pendingHold?.hold
            ? t('remediationHub.tasks.holdButton', 'Put task on hold')
            : t('remediationHub.tasks.resumeButton', 'Resume task')
        }
        handleConfirm={applyHold}
      />
    </PageStack>
  )
}

function BoardColumn({
  state,
  tasks,
  ownerOf,
  canDrag,
}: {
  state: TaskState
  tasks: RemediationTask[]
  ownerOf: (t: RemediationTask) => string
  canDrag: boolean
}) {
  const { t } = useTranslation()
  const { setNodeRef, isOver } = useDroppable({ id: state })
  return (
    <section
      ref={setNodeRef}
      aria-label={t(`remediationHub.state.${state}`)}
      className={cn('bg-muted/40 min-h-40 rounded-lg p-2', isOver && 'ring-primary/50 ring-2')}
    >
      <h3 className="mb-2 flex items-center justify-between px-1 text-sm font-medium">
        {t(`remediationHub.state.${state}`)}
        <span className="text-muted-foreground text-xs">{tasks.length}</span>
      </h3>
      <div className="space-y-2">
        {tasks.map((task) => (
          <DraggableTask key={task.id} task={task} owner={ownerOf(task)} disabled={!canDrag} />
        ))}
      </div>
    </section>
  )
}

function DraggableTask({
  task,
  owner,
  disabled,
}: {
  task: RemediationTask
  owner: string
  disabled: boolean
}) {
  const { attributes, listeners, setNodeRef, transform, isDragging } = useDraggable({
    id: task.id,
    disabled,
  })
  const style = transform
    ? { transform: `translate3d(${transform.x}px, ${transform.y}px, 0)` }
    : undefined
  return (
    <div
      ref={setNodeRef}
      style={style}
      {...listeners}
      {...attributes}
      className={cn(isDragging && 'opacity-60')}
    >
      <TaskCard task={task} owner={owner} />
    </div>
  )
}

export function TaskCard({
  task,
  owner,
  className,
}: {
  task: RemediationTask
  owner: string
  className?: string
}) {
  const { t } = useTranslation()
  return (
    <div className={cn('bg-card rounded-md border p-3 text-sm', className)}>
      <Link href={`/remediation/tasks/${task.id}`} className="font-medium hover:underline">
        {task.title}
      </Link>
      <div className="text-muted-foreground mt-1 truncate text-xs">{owner}</div>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <TaskStatePill state={task.state} />
        <DeadlinePill task={task} />
      </div>
      <TaskProgress task={task} className="mt-2" />
      <div className="text-muted-foreground mt-1 text-xs">
        {t('remediationHub.tasks.verifiedOf', undefined, {
          verified: task.counts.verified,
          total: task.counts.total,
        })}
      </div>
    </div>
  )
}
