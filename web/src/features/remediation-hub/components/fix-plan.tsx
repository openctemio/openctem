'use client'

/**
 * The fix plan: open remediation tasks ranked by the risk each one removes,
 * "do these first". One server-paged table on the list kit, with the running
 * share of the list's risk the top N remove, so the order reads as a plan.
 *
 * Every figure comes from the server: the ranks and the running total come
 * from the rows of a risk-sorted list that starts at rank 1, and the share
 * is shown only when every task of the list is on screen (otherwise its
 * denominator would be a guess). Suggestions to review keep their own tab,
 * which carries their count.
 */

import { useCallback, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import type { ColumnDef, SortingState } from '@tanstack/react-table'
import { ListChecks } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import {
  DataTable,
  FilterSelect,
  FilterToggle,
  MetricStrip,
  RowNameLink,
  type MetricStripItem,
} from '@/features/shared'
import { EmptyState } from '@/features/shared/components/empty-state'
import { MetaLine } from '@/features/shared/components/text-layout'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { SlaDueChip } from '@/features/sla/components/sla-due-chip'
import { useRemediationCampaigns } from '@/features/remediation/api/use-remediation-campaigns'
import { useUrlFilter } from '@/hooks/use-url-param'
import { useSearchQuery } from '@/hooks/use-search-query'
import { formatDate } from '@/lib/app-locale'
import { cn } from '@/lib/utils'
import type { RemediationTask } from '../api/types'
import { type TaskListFilters, useTasks } from '../api/use-remediation-hub'
import { useOwnerLabels } from '../api/use-owner-names'
import { deadlineStatus } from '../lib/hub'
import { TaskProgress, TaskStatePill } from './task-bits'
import { VIEW_FILTERS, type TaskView } from './task-views'

/** The task states the State filter offers ("My tasks" is the Mine toggle). */
const STATE_VIEWS: TaskView[] = ['open', 'verifying', 'on_hold', 'closed', 'all']

/** The orders the API can return; risk removed (the rank) is the plan's own. */
type PlanSort = 'risk' | 'deadline'

/**
 * Table frame widths (px) under which a column folds away, as a running sum
 * in the order the columns join: the ranked task, risk, state and deadline stay
 * from the narrowest table; then findings, the running share, progress and
 * the owner.
 */
export const PLAN_HIDE_BELOW = {
  findings: 720,
  share: 830,
  progress: 960,
  owner: 1110,
} as const

export interface PlanRow {
  task: RemediationTask
  /** 1-based place in the risk order, or undefined in another order. */
  rank?: number
  /** Risk points the tasks up to and including this one remove. */
  running?: number
}

/**
 * Ranks and running totals of a risk-sorted list, exact only for a page that
 * starts at rank 1 (`offset` 0): a later page's total would need the risk of
 * every row before it. The share needs the whole list's risk, so it is given
 * only when every row is on screen (`complete`).
 */
export function planRows(
  tasks: RemediationTask[],
  { ranked, offset }: { ranked: boolean; offset: number }
): { rows: PlanRow[]; totalRisk: number } {
  let sum = 0
  const rows = tasks.map((task, i) => {
    if (!ranked) return { task }
    sum += Math.max(task.counts.risk_points, 0)
    return { task, rank: offset + i + 1, running: offset === 0 ? sum : undefined }
  })
  return { rows, totalRisk: sum }
}

export function FixPlan() {
  const { t } = useTranslation()
  const router = useRouter()

  const [state, setState] = useUrlFilter('state', 'open')
  const [campaign, setCampaign] = useUrlFilter('campaign', '')
  const [mineParam, setMine] = useUrlFilter('mine', '')
  const [overdueParam, setOverdue] = useUrlFilter('overdue', '')
  const [sortParam, setSort] = useUrlFilter('sort', 'risk')
  const [search, setSearch] = useUrlFilter('q', '')
  const searchTerm = useSearchQuery(search).term
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: 25 })
  const resetPage = useCallback(() => setPagination((p) => ({ ...p, pageIndex: 0 })), [])

  const view: TaskView = STATE_VIEWS.includes(state as TaskView) ? (state as TaskView) : 'open'
  const mine = mineParam === '1'
  const overdue = overdueParam === '1'
  const sort: PlanSort = sortParam === 'deadline' ? 'deadline' : 'risk'
  const campaignId = /^[0-9a-fA-F-]{36}$/.test(campaign) ? campaign : ''

  const filters: TaskListFilters = {
    states: VIEW_FILTERS[view].states,
    mine: mine || undefined,
    overdue: overdue || undefined,
    campaignId: campaignId || undefined,
    search: searchTerm,
    sort,
    page: pagination.pageIndex + 1,
    perPage: pagination.pageSize,
  }
  const list = useTasks(filters)
  const tasks = useMemo(() => list.data?.data ?? [], [list.data])

  // The tiles count on the server with the filters each one applies. The
  // open count is the table's own total while the table shows exactly that.
  const openStates = VIEW_FILTERS.open.states
  const isDefault = view === 'open' && !mine && !overdue && !campaignId && searchTerm === ''
  const openQ = useTasks({ states: openStates, perPage: 1 }, !isDefault)
  const overdueQ = useTasks({ states: openStates, overdue: true, perPage: 1 })
  const mineQ = useTasks({ states: openStates, mine: true, perPage: 1 })

  // Campaign names load when the filter opens, or when the URL names one.
  const [campaignsWanted, setCampaignsWanted] = useState(false)
  const campaigns = useRemediationCampaigns({ perPage: 100 }, campaignsWanted || campaignId !== '')

  // Names of the owners on this page only, looked up by id (not the whole member list).
  const owners = useOwnerLabels(
    tasks.map((x) => x.assignee_user_id),
    tasks.map((x) => x.assignee_group_id)
  )

  const ranked = sort === 'risk'
  const { rows, totalRisk } = useMemo(
    () => planRows(tasks, { ranked, offset: pagination.pageIndex * pagination.pageSize }),
    [tasks, ranked, pagination.pageIndex, pagination.pageSize]
  )
  const total = list.data?.total ?? 0
  // Every task of the list is on screen: the share of its risk is exact.
  const complete = ranked && pagination.pageIndex === 0 && !!list.data && total <= tasks.length

  const ownerOf = useCallback(
    (task: RemediationTask) =>
      !task.assignee_user_id && !task.assignee_group_id
        ? t('remediationHub.owner.unassigned')
        : [
            task.assignee_user_id &&
              (owners.user(task.assignee_user_id) ?? t('remediationHub.ownerPicker.unknown')),
            task.assignee_group_id &&
              (owners.group(task.assignee_group_id) ?? t('remediationHub.ownerPicker.unknown')),
          ]
            .filter(Boolean)
            .join(', '),
    [owners, t]
  )
  const openTask = useCallback(
    (task: RemediationTask) => router.push(`/remediation/tasks/${encodeURIComponent(task.id)}`),
    [router]
  )

  const columns = useMemo<ColumnDef<PlanRow>[]>(() => {
    const cols: ColumnDef<PlanRow>[] = []
    cols.push(
      {
        id: 'title',
        header: ranked
          ? t('remediationHub.plan.columns.rankTask')
          : t('remediationHub.tasks.columns.task'),
        enableSorting: false,
        meta: { kind: 'name', label: t('remediationHub.tasks.columns.task') },
        // The rank leads the name, so the name stays the row's first column.
        cell: ({ row }) => (
          <div className="flex min-w-0 items-center gap-3">
            {row.original.rank !== undefined && (
              <span
                data-slot="plan-rank"
                className="text-muted-foreground w-6 shrink-0 text-end font-mono text-sm tabular-nums"
              >
                {row.original.rank}
              </span>
            )}
            <RowNameLink
              href={`/remediation/tasks/${encodeURIComponent(row.original.task.id)}`}
              onOpen={() => openTask(row.original.task)}
              title={row.original.task.title}
              className="block flex-1"
            >
              {row.original.task.title}
            </RowNameLink>
          </div>
        ),
      },
      {
        id: 'findings',
        header: t('remediationHub.plan.columns.findings'),
        enableSorting: false,
        meta: {
          kind: 'number',
          label: t('remediationHub.plan.columns.findings'),
          hideBelow: PLAN_HIDE_BELOW.findings,
        },
        cell: ({ row }) => (
          <span className="font-mono text-sm tabular-nums">{row.original.task.counts.total}</span>
        ),
      },
      {
        id: 'risk',
        header: t('remediationHub.plan.columns.risk'),
        meta: {
          kind: 'number',
          label: t('remediationHub.plan.columns.risk'),
          headerHint: t('remediationHub.risk.explain'),
          width: 88,
        },
        cell: ({ row }) => (
          <span className="font-mono text-sm tabular-nums">
            {row.original.task.counts.risk_points}
          </span>
        ),
      }
    )
    if (ranked && pagination.pageIndex === 0) {
      cols.push({
        id: 'share',
        header: t('remediationHub.plan.columns.share'),
        enableSorting: false,
        meta: {
          kind: 'text',
          label: t('remediationHub.plan.columns.share'),
          headerHint: t('remediationHub.plan.shareHint'),
          width: 104,
          hideBelow: PLAN_HIDE_BELOW.share,
        },
        cell: ({ row }) => (
          <RunningShare
            rank={row.original.rank ?? 0}
            running={row.original.running ?? 0}
            total={complete ? totalRisk : undefined}
          />
        ),
      })
    }
    cols.push(
      {
        id: 'state',
        header: t('remediationHub.tasks.columns.state'),
        enableSorting: false,
        meta: { kind: 'status', label: t('remediationHub.tasks.columns.state') },
        cell: ({ row }) => <TaskStatePill state={row.original.task.state} />,
      },
      {
        id: 'owner',
        header: t('remediationHub.tasks.columns.owner'),
        enableSorting: false,
        meta: {
          kind: 'owner',
          label: t('remediationHub.tasks.columns.owner'),
          hideBelow: PLAN_HIDE_BELOW.owner,
        },
        cell: ({ row }) => (
          <span className="block truncate text-sm" title={ownerOf(row.original.task)}>
            {ownerOf(row.original.task)}
          </span>
        ),
      },
      {
        id: 'deadline',
        header: t('remediationHub.tasks.columns.deadline'),
        meta: { kind: 'due', label: t('remediationHub.tasks.columns.deadline'), width: 168 },
        cell: ({ row }) => <PlanDeadline task={row.original.task} />,
      },
      {
        id: 'progress',
        header: t('remediationHub.tasks.columns.progress'),
        enableSorting: false,
        meta: {
          kind: 'text',
          label: t('remediationHub.tasks.columns.progress'),
          width: 128,
          hideBelow: PLAN_HIDE_BELOW.progress,
        },
        cell: ({ row }) => <PlanProgress task={row.original.task} />,
      }
    )
    return cols
  }, [complete, openTask, ownerOf, pagination.pageIndex, ranked, t, totalRisk])

  // The API sorts each order one way: risk from most to least, deadline from
  // the soonest. A header click picks the order; its direction stays.
  const sorting = useMemo<SortingState>(() => [{ id: sort, desc: sort === 'risk' }], [sort])
  const onSortingChange = useCallback(
    (next: SortingState) => {
      const id = next[0]?.id
      setSort(id === 'deadline' ? 'deadline' : 'risk')
      resetPage()
    },
    [resetPage, setSort]
  )

  const num = (q: { data?: { total: number } }) => (q.data ? q.data.total : '—')
  const openCount = isDefault ? num(list) : num(openQ)
  const setOnly = useCallback(
    (next: { mine?: boolean; overdue?: boolean }) => {
      setState('open')
      setMine(next.mine ? '1' : '')
      setOverdue(next.overdue ? '1' : '')
      setCampaign('')
      setSearch('')
      resetPage()
    },
    [resetPage, setCampaign, setMine, setOverdue, setSearch, setState]
  )
  const metrics: MetricStripItem[] = [
    {
      key: 'open',
      label: t('remediationHub.plan.openTasks'),
      value: openCount,
      onClick: () => setOnly({}),
      active: view === 'open' && !mine && !overdue && !campaignId,
    },
    {
      key: 'overdue',
      label: t('remediationHub.plan.overdue'),
      value: num(overdueQ),
      tone: 'danger',
      onClick: () => setOnly({ overdue: !overdue }),
      active: view === 'open' && overdue && !mine,
    },
    {
      key: 'mine',
      label: t('remediationHub.plan.mine'),
      value: num(mineQ),
      onClick: () => setOnly({ mine: !mine }),
      active: view === 'open' && mine && !overdue,
    },
  ]
  const stripLoading = [isDefault ? list : openQ, overdueQ, mineQ].some(
    (q) => q.isLoading && !q.data
  )

  const filtered = view !== 'open' || mine || overdue || campaignId !== '' || searchTerm !== ''
  const clearFilters = useCallback(() => setOnly({}), [setOnly])

  const campaignOptions = useMemo(() => {
    const opts = (campaigns.data?.data ?? []).map((c) => ({ value: c.id, label: c.name }))
    // The chosen campaign keeps a label while the list loads or when it is
    // not among the first hundred.
    if (campaignId && !opts.some((o) => o.value === campaignId)) {
      opts.unshift({ value: campaignId, label: t('remediationHub.plan.campaignChosen') })
    }
    return opts
  }, [campaignId, campaigns.data, t])

  const toolbarStart = (
    <>
      <FilterSelect<TaskView>
        label={t('remediationHub.tasks.columns.state')}
        value={view}
        clearable={false}
        foldLabel
        options={STATE_VIEWS.map((v) => ({ value: v, label: t(`remediationHub.tasks.view.${v}`) }))}
        onChange={(v) => {
          setState(v || 'open')
          resetPage()
        }}
      />
      <FilterSelect<string>
        label={t('remediationHub.plan.campaign')}
        value={campaignId}
        foldLabel
        options={campaignOptions}
        onOpenChange={(open) => open && setCampaignsWanted(true)}
        onChange={(v) => {
          setCampaign(v)
          resetPage()
        }}
      />
      {/* From 768 px the tiles above the table are these two filters. */}
      <div className="contents md:hidden">
        <FilterToggle
          label={t('remediationHub.plan.mineToggle')}
          pressed={mine}
          onPressedChange={(on) => {
            setMine(on ? '1' : '')
            resetPage()
          }}
        />
        <FilterToggle
          label={t('remediationHub.plan.overdue')}
          pressed={overdue}
          onPressedChange={(on) => {
            setOverdue(on ? '1' : '')
            resetPage()
          }}
        />
      </div>
      {/* Cards have no column headers: the order is a choice of the Filters sheet there. */}
      <Select value={sort} onValueChange={(v) => onSortingChange([{ id: v, desc: v === 'risk' }])}>
        <SelectTrigger
          className="w-44 md:hidden"
          aria-label={t('remediationHub.tasks.sort')}
          data-slot="plan-sort"
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {(['risk', 'deadline'] as const).map((s) => (
            <SelectItem key={s} value={s}>
              {t(`remediationHub.plan.sortBy.${s}`)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </>
  )

  return (
    <>
      <MetricStrip items={metrics} loading={stripLoading} listFirst />
      <DataTable
        columns={columns}
        data={rows}
        caption={t('remediationHub.plan.list')}
        search={{
          value: search,
          onChange: (v: string) => {
            setSearch(v)
            resetPage()
          },
          placeholder: t('remediationHub.tasks.search'),
        }}
        toolbarStart={toolbarStart}
        isLoading={list.isLoading}
        error={list.error && !list.data ? list.error : undefined}
        errorTitle={t('remediationHub.plan.loadError')}
        onRetry={() => void list.mutate()}
        isFiltered={filtered}
        onClearFilters={clearFilters}
        emptyState={{
          nothingYet: (
            <EmptyState
              icon={ListChecks}
              title={t('remediationHub.plan.emptyTitle')}
              description={t('remediationHub.plan.emptyDescription')}
              card
            />
          ),
          noMatch: {
            title: t('remediationHub.tasks.noMatchTitle'),
            hint: t('remediationHub.tasks.noMatchHint'),
          },
        }}
        manualPagination
        rowCount={total}
        pageCount={list.data ? Math.max(1, Math.ceil(total / pagination.pageSize)) : 1}
        pagination={pagination}
        onPaginationChange={setPagination}
        sorting={sorting}
        onSortingChange={onSortingChange}
        getRowId={(r) => r.task.id}
        onRowClick={(r) => openTask(r.task)}
        paginationNoun={t('remediationHub.tasks.noun')}
        mobileRow={(r) => <PlanPhoneCard row={r} onOpen={() => openTask(r.task)} />}
      />
    </>
  )
}

/**
 * "62%" over a bar, the share of the list's risk the tasks up to this one
 * remove, when the whole list is on screen; otherwise the running total in
 * risk points (exact from rank 1), without a bar that would need a guess.
 */
export function RunningShare({
  rank,
  running,
  total,
}: {
  rank: number
  running: number
  total?: number
}) {
  const { t } = useTranslation()
  if (total === undefined || total <= 0) {
    const label = t('remediationHub.plan.runningPoints', undefined, { rank, points: running })
    return (
      <span
        data-slot="plan-running"
        className="text-muted-foreground block truncate text-sm tabular-nums"
        title={label}
      >
        {t('remediationHub.plan.points', undefined, { points: running })}
      </span>
    )
  }
  const pct = Math.min(100, Math.round((running / total) * 100))
  const label = t('remediationHub.plan.runningShare', undefined, {
    rank,
    pct,
    points: running,
    total,
  })
  return (
    <div data-slot="plan-running" className="flex w-full min-w-0 flex-col justify-center gap-1">
      <span className="text-xs leading-4 tabular-nums">{`${pct}%`}</span>
      <div
        role="meter"
        aria-label={label}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={pct}
        title={label}
        className="bg-muted h-1 w-full overflow-hidden rounded-full"
      >
        <span className="bg-primary block h-full" style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

/**
 * The deadline in a list: the short date (the year only when it is not this
 * one), and once it has passed the compact "N d overdue" mark of the SLA
 * chip, as on My work. The full date and what set it are the title. On a
 * phone card (`compact`) a passed deadline is the mark alone.
 */
export function PlanDeadline({ task, compact }: { task: RemediationTask; compact?: boolean }) {
  const { t } = useTranslation()
  if (!task.deadline || deadlineStatus(task.deadline) === 'none') {
    return (
      <span className="text-muted-foreground text-sm">{t('remediationHub.deadline.none')}</span>
    )
  }
  const due = new Date(task.deadline)
  const sameYear = due.getFullYear() === new Date().getFullYear()
  const short = formatDate(due, {
    day: 'numeric',
    month: 'short',
    ...(sameYear ? {} : { year: 'numeric' }),
  })
  const full = formatDate(due, { day: 'numeric', month: 'long', year: 'numeric' })
  const late = deadlineStatus(task.deadline) === 'overdue'
  const source = task.deadline_source
    ? t(`remediationHub.deadline.source.${task.deadline_source}`)
    : undefined
  return (
    <span
      data-slot="plan-deadline"
      className="inline-flex min-w-0 items-center gap-1.5 whitespace-nowrap text-sm"
      title={[full, source].filter(Boolean).join(', ')}
    >
      {!(compact && late) && (
        <span className={cn('tabular-nums', late && 'text-destructive')}>{short}</span>
      )}
      {late && <SlaDueChip status="overdue" deadline={task.deadline} />}
    </span>
  )
}

/**
 * A fix on a phone: the rank, the title on up to two lines of its own, then
 * the risk it removes and the deadline, with the state at the end:
 *   3  Upgrade OpenSSH on 14 hosts in the
 *      payments network
 *      16 risk points  23 d overdue             In progress
 * A tap opens the task.
 */
export function PlanPhoneCard({ row, onOpen }: { row: PlanRow; onOpen: () => void }) {
  const { t } = useTranslation()
  const { task, rank } = row
  return (
    <div data-slot="plan-card" className="flex min-w-0 gap-3 px-3 py-3">
      {rank !== undefined && (
        <span className="text-muted-foreground w-6 shrink-0 text-end font-mono text-sm leading-6 tabular-nums">
          {rank}
        </span>
      )}
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <RowNameLink
          href={`/remediation/tasks/${encodeURIComponent(task.id)}`}
          onOpen={onOpen}
          title={task.title}
          lines={2}
          className="[overflow-wrap:anywhere]"
        >
          {task.title}
        </RowNameLink>
        {/* The facts never break inside; the state moves under them when they do not fit. */}
        <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
          <MetaLine
            className="shrink-0 whitespace-nowrap"
            items={[
              <span key="risk" className="tabular-nums" title={t('remediationHub.risk.explain')}>
                {t('remediationHub.plan.riskRemoved', undefined, {
                  risk: task.counts.risk_points,
                })}
              </span>,
              <PlanDeadline key="deadline" task={task} compact />,
            ]}
          />
          <TaskStatePill state={task.state} className="ms-auto shrink-0" />
        </div>
      </div>
    </div>
  )
}

/** TEMP until the shared progress cell lands: the count over the task's bar. */
function PlanProgress({ task }: { task: RemediationTask }) {
  const { t } = useTranslation()
  return (
    <div className="flex w-full min-w-0 flex-col justify-center gap-1">
      <span className="text-muted-foreground truncate text-xs leading-4 tabular-nums">
        {t('remediationHub.tasks.verifiedOf', undefined, {
          verified: task.counts.verified,
          total: task.counts.total,
        })}
      </span>
      <TaskProgress task={task} />
    </div>
  )
}
