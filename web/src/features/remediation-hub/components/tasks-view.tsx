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
import {
  DataTable,
  FilterSelect,
  ListToolbar,
  PageStack,
  ToolbarAction,
  ViewSwitcher,
} from '@/features/shared'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { MetaLine } from '@/features/shared/components/text-layout'
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

/** Table frame widths (px) under which a column folds away; the name and the state stay. */
export const TASK_HIDE_BELOW = { owner: 560, risk: 720, progress: 860 } as const

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
        .join(', ') || t('remediationHub.owner.unassigned'),
    [owners, t]
  )

  // Board order: the task, who owns it, where it stands, how far it got, the
  // risk it removes, then the deadline. Widths come from the column kinds.
  const columns = useMemo<ColumnDef<RemediationTask>[]>(
    () => [
      {
        accessorKey: 'title',
        header: t('remediationHub.tasks.columns.task'),
        meta: { kind: 'name', label: t('remediationHub.tasks.columns.task') },
        cell: ({ row }) => (
          <div className="min-w-0">
            <Link
              href={`/remediation/tasks/${row.original.id}`}
              className="block truncate font-medium hover:underline"
              title={row.original.title}
            >
              {row.original.title}
            </Link>
            {row.original.action_title && row.original.action_title !== row.original.title && (
              <div className="text-muted-foreground truncate text-xs">
                {row.original.action_title}
              </div>
            )}
          </div>
        ),
      },
      {
        id: 'owner',
        header: t('remediationHub.tasks.columns.owner'),
        meta: {
          kind: 'owner',
          label: t('remediationHub.tasks.columns.owner'),
          hideBelow: TASK_HIDE_BELOW.owner,
        },
        cell: ({ row }) => (
          <span className="block truncate text-sm" title={ownerOf(row.original)}>
            {ownerOf(row.original)}
          </span>
        ),
      },
      {
        accessorKey: 'state',
        header: t('remediationHub.tasks.columns.state'),
        meta: { kind: 'status', label: t('remediationHub.tasks.columns.state') },
        cell: ({ row }) => <TaskStatePill state={row.original.state} />,
      },
      {
        id: 'progress',
        header: t('remediationHub.tasks.columns.progress'),
        meta: {
          kind: 'text',
          label: t('remediationHub.tasks.columns.progress'),
          width: 160,
          hideBelow: TASK_HIDE_BELOW.progress,
        },
        cell: ({ row }) => (
          <div className="w-full min-w-0">
            <TaskProgress task={row.original} />
            <div className="text-muted-foreground mt-1 truncate text-xs">
              {t('remediationHub.tasks.verifiedOf', undefined, {
                verified: row.original.counts.verified,
                total: row.original.counts.total,
              })}
            </div>
          </div>
        ),
      },
      {
        id: 'risk',
        header: t('remediationHub.tasks.columns.risk'),
        meta: {
          kind: 'number',
          label: t('remediationHub.tasks.columns.risk'),
          headerHint: t('remediationHub.risk.explain'),
          hideBelow: TASK_HIDE_BELOW.risk,
        },
        cell: ({ row }) => (
          <span className="font-mono text-sm tabular-nums">{row.original.counts.risk_points}</span>
        ),
      },
      {
        accessorKey: 'deadline',
        header: t('remediationHub.tasks.columns.deadline'),
        meta: { kind: 'due', label: t('remediationHub.tasks.columns.deadline') },
        cell: ({ row }) => <DeadlinePill task={row.original} />,
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

  const filtered = searchTerm !== '' || view !== defaultView
  const clearFilters = useCallback(() => {
    setSearch('')
    setParam('view', defaultView)
  }, [defaultView, setParam])

  // One toolbar for both layouts: which tasks (a filter token, not a second
  // row of tabs under the section tabs) and the search; then sort, the
  // table/board switch and the create action at the end.
  const toolbarSearch = {
    value: search,
    onChange: (v: string) => {
      setSearch(v)
      setPagination((p) => ({ ...p, pageIndex: 0 }))
    },
    placeholder: t('remediationHub.tasks.search'),
  }
  // The order is a token of the start group: on a phone it moves into the
  // Filters sheet with the Show filter, so the list comes first.
  const toolbarStart = (
    <>
      <FilterSelect<TaskView>
        label={t('remediationHub.tasks.showLabel', 'Show')}
        value={view}
        clearable={false}
        options={viewLabels.map((v) => ({
          value: v,
          label: t(`remediationHub.tasks.view.${v}`),
        }))}
        onChange={(v) => setParam('view', v || defaultView)}
      />
      <Select value={sort} onValueChange={(v) => setSort(v as TaskListFilters['sort'])}>
        <SelectTrigger className="w-40" aria-label={t('remediationHub.tasks.sort')}>
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
    </>
  )
  const toolbarEnd = (
    <>
      <ViewSwitcher
        options={[
          { value: 'table', label: t('remediationHub.tasks.table'), icon: Table2 },
          { value: 'board', label: t('remediationHub.tasks.board'), icon: LayoutGrid },
        ]}
        value={layout === 'board' ? 'board' : 'table'}
        onChange={(v) => setParam('layout', v)}
      />
      {canQueryCreate && (
        <ToolbarAction
          icon={SquareCode}
          label={t('remediationQuery.create.entry')}
          onClick={() => setQueryOpen(true)}
        />
      )}
    </>
  )
  const nothingYet = (
    <EmptyState
      icon={ClipboardList}
      title={t('remediationHub.tasks.emptyTitle')}
      description={t('remediationHub.tasks.emptyDescription')}
      action={
        <Button asChild variant="outline">
          <Link href="/remediation/suggestions">{t('remediationHub.tasks.reviewSuggestions')}</Link>
        </Button>
      }
      card
    />
  )

  return (
    <PageStack>
      {canQueryCreate && <CreateTaskFromQueryDialog open={queryOpen} onOpenChange={setQueryOpen} />}

      {layout === 'table' ? (
        <DataTable
          columns={columns}
          data={tasks}
          search={toolbarSearch}
          toolbarStart={toolbarStart}
          toolbarEnd={toolbarEnd}
          isLoading={isLoading}
          error={error && !data ? error : undefined}
          errorTitle={t('remediationHub.tasks.loadError')}
          onRetry={() => void mutate()}
          isFiltered={filtered}
          onClearFilters={clearFilters}
          emptyState={{
            nothingYet,
            noMatch: {
              title: t('remediationHub.tasks.noMatchTitle'),
              hint: t('remediationHub.tasks.noMatchHint'),
            },
          }}
          manualPagination
          rowCount={data?.total ?? 0}
          pageCount={data ? Math.max(1, Math.ceil(data.total / pagination.pageSize)) : 1}
          pagination={pagination}
          onPaginationChange={setPagination}
          getRowId={(r) => r.id}
          onRowClick={(r) => router.push(`/remediation/tasks/${r.id}`)}
          paginationNoun={t('remediationHub.tasks.noun')}
          mobileRow={(r) => <TaskPhoneCard task={r} owner={ownerOf(r)} />}
        />
      ) : (
        <>
          <ListToolbar search={toolbarSearch} start={toolbarStart} end={toolbarEnd} />
          {error && !data ? (
            <ErrorState
              title={t('remediationHub.tasks.loadError')}
              error={error}
              onRetry={() => void mutate()}
            />
          ) : !isLoading && tasks.length === 0 && !filtered ? (
            nothingYet
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
        </>
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

/**
 * A task on a phone (board M-Remediation):
 *   Upgrade OpenSSH on 14 hosts ....................... In progress
 *   Platform team
 *   14 of 31 findings resolved   2 d overdue
 * A tap opens the task.
 */
export function TaskPhoneCard({ task, owner }: { task: RemediationTask; owner: string }) {
  const { t } = useTranslation()
  return (
    <div data-slot="task-card" className="flex min-w-0 flex-col gap-1 px-3 py-3">
      <div className="flex min-w-0 items-center justify-between gap-3">
        <Link
          href={`/remediation/tasks/${task.id}`}
          className="min-w-0 truncate font-medium hover:underline"
          title={task.title}
        >
          {task.title}
        </Link>
        <TaskStatePill state={task.state} className="shrink-0" />
      </div>
      <p className="text-meta truncate" title={owner}>
        {owner}
      </p>
      <MetaLine
        items={[
          <span key="progress" className="tabular-nums">
            {t('remediationHub.tasks.verifiedOf', undefined, {
              verified: task.counts.verified,
              total: task.counts.total,
            })}
          </span>,
          <DeadlinePill key="deadline" task={task} />,
        ]}
      />
    </div>
  )
}
