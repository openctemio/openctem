'use client'

/**
 * One remediation task: what to do (fix steps), how far it is (verified,
 * closed, claimed, open), its findings grouped by asset (a windowed list
 * that loads as you scroll), and its timeline. Select findings to move them
 * (palette or drag onto a task of the same fix), split them off, or mark the
 * task fixed. Every change names the version it was based on; a move can be
 * undone from its toast.
 *
 * On the shared detail kit, like the finding page (board P2-RemediationTask):
 *
 *   header: state, campaign, title, [More] [Request exception] [Mark fixed]
 *   tabs:   Findings N | Fix steps | Timeline
 *   ┌──────────────────────────────────────┬────────────────┐
 *   │ bands (exception, hidden findings)   │ Details        │
 *   │ the tab's panel                      │ (sticky rail)  │
 *   └──────────────────────────────────────┴────────────────┘
 *
 * Only the open tab loads: the timeline and the query wait for their tab,
 * the watchers for a click, the tasks of the same fix for a selection.
 */

import { FindingTitleCell } from '@/features/findings/components/cells/finding-title-cell'
import { useBreadcrumbTitle } from '@/components/layout'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import useSWRInfinite from 'swr/infinite'
import {
  DndContext,
  type DragEndEvent,
  PointerSensor,
  useDraggable,
  useDroppable,
  useSensor,
  useSensors,
} from '@dnd-kit/core'
import {
  CheckCheck,
  EyeOff,
  GripVertical,
  History,
  ListChecks,
  MoveRight,
  Scissors,
  Wrench,
} from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { get } from '@/lib/api/client'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsCount, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ErrorState } from '@/features/shared/components/error-state'
import { PageStack } from '@/features/shared/components/page-stack'
import {
  DetailPageHeader,
  PropertyGroup,
  PropertyList,
  PropertyRow,
} from '@/features/shared/components/detail'
import { DetailCallout } from '@/features/shared/components/detail-sheet'
import { useDetailTab } from '@/features/shared/components/detail-sheet-layout'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import type { Severity } from '@/features/shared'
import { cn } from '@/lib/utils'
import { formatNumber } from '@/lib/app-locale'
import { useIsMobile } from '@/hooks/use-mobile'
import { requestOwnerAccess } from '../api/use-owner-access'
import {
  TERMINAL_TASK_STATES,
  type Page,
  type RemediationTask,
  type TaskMember,
} from '../api/types'
import {
  hubApi,
  memberPageUrl,
  useRevalidateHub,
  useTask,
  useTasks,
} from '../api/use-remediation-hub'
import { useOwnerLabels } from '../api/use-owner-names'
import { TaskPeople } from './task-people'
import { fixSteps, groupByAsset, isTypingTarget } from '../lib/hub'
import { FixStepsBlock } from './fix-steps'
import { MovePalette, type MoveTarget } from './move-palette'
import { apiMessage } from './suggestions-inbox'
import { SplitDialog } from './task-dialogs'
import { useTaskActions } from './use-task-actions'
import { DeadlinePill, TaskCampaignLink, TaskProgress, TaskStatePill } from './task-bits'
import { useTaskException } from './task-exception'
import { TaskHistory } from './task-history'
import { VirtualRows } from './virtual-rows'
import { TaskFindingDrawer } from './task-finding-drawer'
import { TaskRowStatus } from './task-row-status'
import { nextWorkFinding, positionOf, stepFinding } from '../lib/task-nav'
import type { FindingStatus } from '@/features/findings/types'

const MEMBER_PAGE = 200

const TASK_TABS = ['findings', 'fix', 'timeline'] as const
type TaskTab = (typeof TASK_TABS)[number]

// The finding page's grid (web/src/app/(dashboard)/findings/[id]/page.tsx):
// from 1280 px the details are a sticky rail beside the tab's panel; below,
// the bands come first, then the details, then the tabs and the panel.
const GRID = 'grid min-w-0 xl:grid-cols-[minmax(0,1fr)_19rem]'
const RAIL = 'min-w-0 max-xl:order-2 xl:sticky xl:top-4 xl:col-start-2 xl:row-start-2 xl:self-start'
const STRIP = 'min-w-0 max-xl:order-3 xl:col-span-2 xl:row-start-1'
const MAIN = 'flex min-w-0 flex-col gap-page max-xl:contents xl:col-start-1 xl:row-start-2'
// Two lines: the title and the target under it (FindingTitleCell).
const ROW_HEIGHT = 52
// A phone: two title lines and the target, then the severity and status
// (py-2 + 2 x 20 + 16 + gap 4 + a 36 px control).
const PHONE_ROW_HEIGHT = 112
const GROUP_HEIGHT = 40

type Row =
  | { kind: 'group'; key: string; label: string; count: number }
  | { kind: 'member'; member: TaskMember }

export function TaskDetail({ taskId }: { taskId: string }) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const canWrite = hasPermission(Permission.RemediationWrite)
  const revalidate = useRevalidateHub()
  const { data: task, error, isLoading, mutate } = useTask(taskId)
  // The owner's name by id: the first view never loads the member list.
  const owners = useOwnerLabels([task?.assignee_user_id], [task?.assignee_group_id])
  useBreadcrumbTitle(task?.title)
  const members = useSWRInfinite<Page<TaskMember>>(
    (index, prev) =>
      prev && prev.data.length < MEMBER_PAGE ? null : memberPageUrl(taskId, index + 1, MEMBER_PAGE),
    get
  )
  const loaded = useMemo(() => (members.data ?? []).flatMap((p) => p.data), [members.data])
  const totalMembers = members.data?.[0]?.total ?? 0
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [moveOpen, setMoveOpen] = useState(false)
  const [dropTarget, setDropTarget] = useState<RemediationTask | null>(null)
  const [splitOpen, setSplitOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [tab, setTab] = useDetailTab<TaskTab>('tab', TASK_TABS)
  const phone = useIsMobile()
  const rowHeight = useCallback(
    (r: Row) => (r.kind === 'group' ? GROUP_HEIGHT : phone ? PHONE_ROW_HEIGHT : ROW_HEIGHT),
    [phone]
  )
  const canComment = hasPermission(Permission.FindingsComment)

  // The finding open in the side drawer lives in the URL (?finding=), so it
  // can be shared; opening pushes (Back closes it), moving inside it replaces.
  const router = useRouter()
  const pathname = usePathname()
  const search = useSearchParams()
  const searchStr = search.toString()
  const findingId = search.get('finding')
  const [activeId, setActiveId] = useState<string | null>(null)
  const [autoNext, setAutoNext] = useState(true)
  useEffect(() => {
    try {
      if (window.localStorage.getItem('remediationHub.autoNext') === '0') setAutoNext(false)
    } catch {
      // no storage: keep the default
    }
  }, [])
  const showFinding = useCallback(
    (id: string | null, mode: 'push' | 'replace') => {
      const q = new URLSearchParams(searchStr)
      if (id) q.set('finding', id)
      else q.delete('finding')
      const qs = q.toString()
      const url = qs ? `${pathname}?${qs}` : pathname
      if (mode === 'push') router.push(url, { scroll: false })
      else router.replace(url, { scroll: false })
      if (id) setActiveId(id)
    },
    [pathname, router, searchStr, setActiveId]
  )
  // The other open tasks of the same fix are drop targets: read them when the
  // person starts to select or drag (pointer down on the list), not with the page.
  const [wantTargets, setWantTargets] = useState(false)
  const { data: siblings, isLoading: targetsLoading } = useTasks(
    {
      actionId: task?.action_id,
      states: ['open', 'in_progress', 'verifying', 'on_hold'],
      perPage: 6,
    },
    !!task && canWrite && (wantTargets || selected.size > 0)
  )

  const refresh = useCallback(async () => {
    setSelected(new Set())
    await Promise.all([mutate(), members.mutate(), revalidate()])
  }, [members, mutate, revalidate])

  const rows = useMemo<Row[]>(() => {
    const out: Row[] = []
    for (const g of groupByAsset(loaded)) {
      out.push({
        kind: 'group',
        key: g.key,
        label: g.label || t('remediationHub.detail.noAsset'),
        count: g.items.length,
      })
      for (const m of g.items) out.push({ kind: 'member', member: m })
    }
    return out
  }, [loaded, t])

  const order = useMemo(
    () => rows.flatMap((r) => (r.kind === 'member' ? [r.member.finding_id] : [])),
    [rows]
  )
  const position = positionOf(order, findingId)
  const onFindingStatus = useCallback(
    (id: string, status: FindingStatus) => {
      void members.mutate()
      void revalidate()
      if (!autoNext || findingId !== id || !['in_progress', 'fix_applied'].includes(status)) return
      const next = nextWorkFinding(
        order,
        (x) => (x === id ? status : loaded.find((m) => m.finding_id === x)?.status),
        id
      )
      if (next) showFinding(next, 'replace')
    },
    [autoNext, findingId, loaded, members, order, revalidate, showFinding]
  )

  const actions = useTaskActions(task, refresh)
  const { writable, canFix } = actions
  const exception = useTaskException(taskId, task?.version ?? 0, writable)

  const doMove = useCallback(
    async (target: MoveTarget) => {
      if (!task) return
      const ids = [...selected]
      setMoveOpen(false)
      setDropTarget(null)
      try {
        const res = await hubApi.move({
          from_task_id: task.id,
          from_version: task.version,
          finding_ids: ids,
          confirm: true,
          ...(target.task ? { to_task_id: target.task.id, to_version: target.task.version } : {}),
        })
        await refresh()
        const canUndo = !!res.target && !!res.source && !res.source_archived
        toast.success(
          target.task
            ? t('remediationHub.toast.moved', undefined, {
                n: res.moved.length,
                title: target.task.title,
              })
            : t('remediationHub.toast.detached', undefined, { n: res.moved.length }),
          canUndo
            ? {
                duration: 10000,
                action: {
                  label: t('remediationHub.actions.undo'),
                  onClick: () => {
                    void hubApi
                      .move({
                        from_task_id: res.target!.id,
                        from_version: res.target!.version,
                        to_task_id: res.source!.id,
                        to_version: res.source!.version,
                        finding_ids: res.moved,
                        confirm: true,
                      })
                      .then(refresh, (err) =>
                        toast.error(apiMessage(err, t('remediationHub.toast.failed')))
                      )
                  },
                },
              }
            : undefined
        )
      } catch (err) {
        toast.error(apiMessage(err, t('remediationHub.toast.failed')))
        await refresh()
      }
    },
    [refresh, selected, t, task]
  )

  const doSplit = useCallback(
    async (body: {
      title: string
      assignee_user_id?: string
      assignee_group_id?: string
      confirm_owner_access?: boolean
    }) => {
      if (!task) return
      setBusy(true)
      try {
        const res = await hubApi.splitTask(task.id, {
          version: task.version,
          finding_ids: [...selected],
          ...body,
        })
        setSplitOpen(false)
        await refresh()
        toast.success(t('remediationHub.toast.split', undefined, { n: res.moved.length }))
      } catch (err) {
        toast.error(apiMessage(err, t('remediationHub.toast.failed')))
      } finally {
        setBusy(false)
      }
    },
    [refresh, selected, t, task]
  )

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (
        moveOpen ||
        splitOpen ||
        actions.dialogOpen ||
        exception.open ||
        e.metaKey ||
        e.ctrlKey ||
        e.altKey ||
        isTypingTarget(e.target)
      )
        return
      const dialogs = document.querySelectorAll('[role="dialog"][data-state="open"]').length
      if (dialogs > (findingId ? 1 : 0)) return
      if (e.key === 'j' || e.key === 'k') {
        const to = stepFinding(order, findingId ?? activeId, e.key === 'j' ? 1 : -1)
        if (to) {
          if (findingId) showFinding(to, 'replace')
          else setActiveId(to)
        }
      } else if (e.key === 'Enter' && !findingId && activeId && e.target === document.body) {
        showFinding(activeId, 'push')
      } else if (e.key === 'm' && writable && selected.size > 0) setMoveOpen(true)
      else if (
        e.key === 's' &&
        writable &&
        selected.size > 0 &&
        selected.size < (task?.counts.total ?? 0)
      )
        setSplitOpen(true)
      else if (e.key === 'f' && writable && canFix) actions.openFix()
      else return
      e.preventDefault()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [
    moveOpen,
    splitOpen,
    actions,
    exception.open,
    writable,
    canFix,
    selected.size,
    task,
    findingId,
    activeId,
    order,
    showFinding,
  ])

  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 6 } }))
  const onDragEnd = useCallback(
    (e: DragEndEvent) => {
      const target = (siblings?.data ?? []).find((x) => x.id === e.over?.id)
      const dragged = String(e.active.id)
      if (!target) return
      if (!selected.has(dragged)) setSelected(new Set([dragged]))
      setDropTarget(target)
      setMoveOpen(true)
    },
    [selected, siblings]
  )

  if (error) {
    return (
      <ErrorState
        title={t('remediationHub.detail.loadError')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !task) {
    return (
      <div className="space-y-4" aria-busy="true">
        <Skeleton className="h-10 w-1/2" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    )
  }

  const owner =
    [owners.user(task.assignee_user_id), owners.group(task.assignee_group_id)]
      .filter(Boolean)
      .join(', ') || t('remediationHub.owner.unassigned')
  const steps = fixSteps(undefined, task.action_key)
  const targets = (siblings?.data ?? []).filter((x) => x.id !== task.id)
  const menu = writable
    ? actions.menu.map((m, i) => ({
        id: `task-action-${i}`,
        label: m.label,
        icon: m.icon,
        destructive: m.destructive,
        onSelect: m.onSelect,
      }))
    : undefined

  return (
    <PageStack>
      <DetailPageHeader
        title={task.title}
        parent={{ href: '/remediation/tasks', label: t('remediationHub.tasks.title') }}
        chips={
          <>
            <TaskStatePill state={task.state} />
            {task.campaign_id && <TaskCampaignLink campaignId={task.campaign_id} inline />}
          </>
        }
        primary={actions.primary}
        secondary={exception.action}
        menu={menu}
        facts={
          <dl className="text-muted-foreground flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
            <div className="flex min-w-0 items-center gap-1">
              <dt className="after:content-[':']">{t('remediationHub.detail.facts.owner')}</dt>
              <dd className="text-foreground min-w-0 truncate">{owner}</dd>
            </div>
            <div className="flex items-center gap-1">
              <dt className="after:content-[':']">{t('remediationHub.detail.deadline')}</dt>
              <dd>
                <DeadlinePill task={task} />
              </dd>
            </div>
          </dl>
        }
      />

      <DndContext sensors={sensors} onDragEnd={onDragEnd}>
        <Tabs value={tab} onValueChange={(v) => setTab(v as TaskTab)} className={GRID}>
          <aside aria-label={t('remediationHub.detail.details')} className={RAIL}>
            <div className="max-md:rounded-lg max-md:border max-md:bg-card max-md:px-3">
              <PropertyList label={t('remediationHub.detail.details')}>
                <PropertyGroup>
                  <PropertyRow label={t('remediationHub.detail.riskLeft')}>
                    <span title={t('remediationHub.risk.explain')}>
                      {t('remediationHub.risk.points', undefined, { n: task.counts.risk_points })}
                    </span>
                  </PropertyRow>
                  <PropertyRow label={t('remediationHub.detail.progress')}>
                    <div
                      className="flex w-full min-w-0 items-center gap-2"
                      title={t('remediationHub.progress.summary', undefined, {
                        verified: task.counts.verified,
                        closed: task.counts.closed,
                        claimed: task.counts.fix_applied,
                        open: task.counts.open + task.counts.in_progress,
                        total: task.counts.total,
                      })}
                    >
                      <div className="min-w-0 flex-1">
                        <TaskProgress task={task} />
                      </div>
                      <span className="text-muted-foreground shrink-0 text-xs tabular-nums">
                        {formatNumber(task.counts.verified + task.counts.closed)}/
                        {formatNumber(task.counts.total)}
                      </span>
                    </div>
                  </PropertyRow>
                </PropertyGroup>
                <TaskPeople taskId={task.id} owner={owner} />
              </PropertyList>
            </div>
            {writable && tab === 'findings' && (wantTargets || selected.size > 0) && (
              <section
                className="mt-4 space-y-2 max-xl:hidden"
                aria-label={t('remediationHub.detail.dropTargets')}
              >
                <h2 className="text-cap-m text-muted-foreground">
                  {t('remediationHub.detail.dropTargets')}
                </h2>
                <p className="text-muted-foreground text-xs">
                  {t('remediationHub.detail.dropHint')}
                </p>
                {targetsLoading && <Skeleton className="h-16 w-full" />}
                {siblings && targets.length === 0 && (
                  <p className="text-muted-foreground text-xs">
                    {t('remediationHub.detail.dropNone')}
                  </p>
                )}
                {targets.map((x) => (
                  <DropTask key={x.id} task={x} />
                ))}
              </section>
            )}
          </aside>

          <div className={STRIP}>
            <TabsList>
              <TabsTrigger value="findings">
                <ListChecks aria-hidden />
                {t('remediationHub.detail.tab.findings')}
                <TabsCount value={task.counts.total} />
              </TabsTrigger>
              <TabsTrigger value="fix">
                <Wrench aria-hidden />
                {t('remediationHub.detail.tab.fix')}
              </TabsTrigger>
              <TabsTrigger value="timeline">
                <History aria-hidden />
                {t('remediationHub.detail.tab.timeline')}
              </TabsTrigger>
            </TabsList>
          </div>

          <div className={MAIN}>
            <div
              data-slot="task-bands"
              className="flex min-w-0 flex-col gap-3 empty:hidden max-xl:order-1"
            >
              {exception.banner}
              {task.hidden_members > 0 && (
                <DetailCallout
                  tone="warning"
                  icon={EyeOff}
                  title={t('remediationHub.detail.hidden', undefined, { n: task.hidden_members })}
                  actions={
                    canComment && loaded[0] ? (
                      <Button
                        variant="outline"
                        onClick={() => {
                          requestOwnerAccess(
                            loaded[0].finding_id,
                            t('remediationHub.detail.hiddenRequest', undefined, {
                              n: task.hidden_members,
                              title: task.title,
                            })
                          ).then(
                            () => toast.success(t('remediationHub.ownerAccess.requested')),
                            () => toast.error(t('remediationHub.ownerAccess.requestFailed'))
                          )
                        }}
                      >
                        {t('remediationHub.ownerAccess.request')}
                      </Button>
                    ) : undefined
                  }
                />
              )}
              {(task.state_note || task.archived_note || task.regression_of) && (
                <div className="text-muted-foreground space-y-1 text-sm">
                  {task.state_note && <p>{task.state_note}</p>}
                  {task.archived_note && <p>{task.archived_note}</p>}
                  {task.regression_of && (
                    <p>
                      <Link
                        href={`/remediation/tasks/${task.regression_of}`}
                        className="text-foreground underline"
                      >
                        {t('remediationHub.detail.regressionOf')}
                      </Link>
                    </p>
                  )}
                </div>
              )}
            </div>

            <div data-slot="task-panel" className="min-w-0 max-xl:order-4">
              <TabsContent value="findings">
                <section
                  className="min-w-0 rounded-lg border"
                  aria-label={t('remediationHub.detail.findingsList')}
                  onPointerDownCapture={() => writable && setWantTargets(true)}
                >
                  <div className="flex min-h-12 flex-wrap items-center gap-x-3 gap-y-2 border-b px-3 py-2">
                    <StatusCounts task={task} />
                    <label className="text-muted-foreground flex min-w-0 items-center gap-1.5 text-xs">
                      <Checkbox
                        checked={autoNext}
                        onCheckedChange={(v) => {
                          setAutoNext(v === true)
                          try {
                            window.localStorage.setItem(
                              'remediationHub.autoNext',
                              v === true ? '1' : '0'
                            )
                          } catch {
                            // not stored: applies to this visit
                          }
                        }}
                      />
                      {t('remediationHub.detail.autoNext')}
                    </label>
                    {writable && selected.size > 0 && (
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-muted-foreground text-xs">
                          {t('remediationHub.detail.selected', undefined, { n: selected.size })}
                        </span>
                        <Button
                          variant="outline"
                          onClick={() => setMoveOpen(true)}
                          aria-keyshortcuts="m"
                        >
                          <MoveRight aria-hidden />
                          {t('remediationHub.detail.moveTo')}
                        </Button>
                        <Button
                          variant="outline"
                          onClick={() => setSplitOpen(true)}
                          disabled={selected.size >= task.counts.total}
                          aria-keyshortcuts="s"
                        >
                          <Scissors aria-hidden />
                          {t('remediationHub.detail.split')}
                        </Button>
                      </div>
                    )}
                  </div>
                  {members.error ? (
                    <ErrorState
                      title={t('remediationHub.detail.membersError')}
                      error={members.error}
                      onRetry={() => void members.mutate()}
                    />
                  ) : !members.data ? (
                    <Skeleton className="m-3 h-40" />
                  ) : rows.length === 0 ? (
                    <p className="text-muted-foreground p-4 text-sm">
                      {t('remediationHub.detail.noFindings')}
                    </p>
                  ) : (
                    <VirtualRows
                      rows={rows}
                      rowHeight={rowHeight}
                      height={480}
                      label={t('remediationHub.detail.findingsList')}
                      scrollToIndex={
                        activeId
                          ? rows.findIndex(
                              (r) => r.kind === 'member' && r.member.finding_id === activeId
                            )
                          : null
                      }
                      rowKey={(r) => (r.kind === 'group' ? `g:${r.key}` : r.member.finding_id)}
                      onEndReached={() => {
                        if (loaded.length < totalMembers && !members.isValidating)
                          void members.setSize(members.size + 1)
                      }}
                      renderRow={(r) =>
                        r.kind === 'group' ? (
                          <div className="bg-muted/50 flex h-full items-center justify-between gap-2 px-3 text-xs font-medium">
                            <span className="min-w-0 truncate">{r.label}</span>
                            <span className="text-muted-foreground">{r.count}</span>
                          </div>
                        ) : (
                          <MemberRow
                            member={r.member}
                            selectable={writable}
                            selected={selected.has(r.member.finding_id)}
                            active={activeId === r.member.finding_id}
                            statusMenu={!TERMINAL_TASK_STATES.has(task.state)}
                            onOpen={() => showFinding(r.member.finding_id, 'push')}
                            onStatus={onFindingStatus}
                            phone={phone}
                            onSelect={(v) =>
                              setSelected((cur) => {
                                const n = new Set(cur)
                                if (v) n.add(r.member.finding_id)
                                else n.delete(r.member.finding_id)
                                return n
                              })
                            }
                          />
                        )
                      }
                    />
                  )}
                </section>
              </TabsContent>
              <TabsContent value="fix">
                <section className="min-w-0 space-y-3 rounded-lg border p-4">
                  <h2 className="text-sm font-semibold break-words">
                    {task.action_title?.trim() || t('remediationHub.detail.tab.fix')}
                  </h2>
                  <FixStepsBlock steps={steps} />
                  <p className="text-muted-foreground text-xs">
                    {t('remediationHub.detail.doneRule')}
                  </p>
                </section>
              </TabsContent>
              <TabsContent value="timeline">
                <TaskHistory task={task} writable={writable} onChanged={() => void mutate()} />
              </TabsContent>
            </div>
          </div>
        </Tabs>
      </DndContext>

      <MovePalette
        open={moveOpen}
        onOpenChange={(o) => {
          setMoveOpen(o)
          if (!o) setDropTarget(null)
        }}
        source={task}
        findingIds={[...selected]}
        onConfirm={(target) => void doMove(target)}
        presetTarget={dropTarget}
      />
      <SplitDialog
        task={task}
        count={selected.size}
        findingIds={[...selected]}
        open={splitOpen}
        onOpenChange={setSplitOpen}
        onConfirm={(body) => void doSplit(body)}
        busy={busy}
      />
      {actions.dialogs}
      {exception.dialog}
      <TaskFindingDrawer
        taskId={taskId}
        findingId={findingId}
        position={position}
        onClose={() => showFinding(null, 'replace')}
        onGo={(id) => showFinding(id, 'replace')}
        onStatusChange={onFindingStatus}
      />
    </PageStack>
  )
}

function MemberRow({
  member: m,
  selectable,
  selected,
  onSelect,
  active,
  statusMenu,
  onOpen,
  onStatus,
  phone,
}: {
  member: TaskMember
  selectable: boolean
  selected: boolean
  onSelect: (v: boolean) => void
  active: boolean
  statusMenu: boolean
  onOpen: () => void
  onStatus: (findingId: string, status: FindingStatus) => void
  phone: boolean
}) {
  const { t } = useTranslation()
  const { attributes, listeners, setNodeRef, transform, isDragging } = useDraggable({
    id: m.finding_id,
    disabled: !selectable || m.role !== 'primary',
  })
  const style = transform
    ? { transform: `translate3d(${transform.x}px, ${transform.y}px, 0)` }
    : undefined
  const title = (
    <button
      type="button"
      onClick={onOpen}
      className={cn(
        'flex min-w-0 flex-1 text-start hover:[&_p]:underline',
        phone ? 'w-full items-start' : 'items-center self-stretch'
      )}
      aria-label={t('remediationHub.detail.openFinding', undefined, {
        title: [m.title, m.asset_name].filter(Boolean).join(', '),
      })}
    >
      <FindingTitleCell title={m.title} target={m.asset_name} titleLines={phone ? 2 : 1} />
    </button>
  )
  const severity = <SeverityBadge severity={m.severity as Severity} />
  const facts = (
    <>
      {m.role === 'related' && (
        <span className="text-muted-foreground text-xs">{t('remediationHub.detail.related')}</span>
      )}
      {statusMenu && m.role === 'primary' ? (
        <TaskRowStatus member={m} onChanged={onStatus} />
      ) : (
        <span className="text-muted-foreground text-xs">
          {t(`remediationHub.findingStatus.${m.status}`, m.status)}
        </span>
      )}
      {m.verified && (
        <CheckCheck
          className="size-4 text-success"
          aria-label={t('remediationHub.detail.verified')}
        />
      )}
    </>
  )
  return (
    <div
      ref={setNodeRef}
      style={style}
      className={cn(
        'flex h-full gap-2 border-b px-3 text-sm',
        phone ? 'items-start py-2' : 'items-center',
        isDragging && 'bg-muted opacity-70',
        active && 'bg-primary/5 ring-primary/50 ring-1 ring-inset'
      )}
    >
      {selectable && m.role === 'primary' && (
        <>
          {/* Drop targets are listed in the rail, from 1280 px only. */}
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="cursor-grab max-xl:hidden"
            aria-label={t('remediationHub.detail.drag', undefined, { title: m.title })}
            {...listeners}
            {...attributes}
          >
            <GripVertical aria-hidden />
          </Button>
          <Checkbox
            className={cn(phone && 'mt-0.5')}
            checked={selected}
            onCheckedChange={(v) => onSelect(v === true)}
            aria-label={t('remediationHub.detail.selectFinding', undefined, { title: m.title })}
          />
        </>
      )}
      {phone ? (
        // A phone gives the title the whole row: two lines and the target,
        // then the severity and the status under it.
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          {title}
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            {severity}
            {facts}
          </div>
        </div>
      ) : (
        <>
          {severity}
          {title}
          <div className="flex shrink-0 items-center gap-2">{facts}</div>
        </>
      )}
    </div>
  )
}

/** The board's count strip: how many findings of the task are at each step. */
function StatusCounts({ task }: { task: RemediationTask }) {
  const { t } = useTranslation()
  const c = task.counts
  const parts: [string, number][] = [
    ['open', c.open],
    ['inProgress', c.in_progress],
    ['fixApplied', c.fix_applied],
    ['verified', c.verified],
    ['closed', c.closed],
  ]
  return (
    <dl
      aria-label={t('remediationHub.detail.counts.label')}
      className="flex min-w-0 flex-1 flex-wrap items-center gap-x-4 gap-y-1 text-xs max-md:basis-full"
    >
      {parts.map(([key, n]) => (
        <div key={key} className="flex items-center gap-1">
          <dt className="text-muted-foreground">{t(`remediationHub.detail.counts.${key}`)}</dt>
          <dd className={cn('font-medium tabular-nums', n === 0 && 'text-muted-foreground')}>
            {formatNumber(n)}
          </dd>
        </div>
      ))}
    </dl>
  )
}

function DropTask({ task }: { task: RemediationTask }) {
  const { setNodeRef, isOver } = useDroppable({ id: task.id })
  return (
    <div
      ref={setNodeRef}
      className={cn(
        'rounded-md border p-2 text-sm',
        isOver && 'ring-primary/60 bg-primary/5 ring-2'
      )}
    >
      <div className="truncate font-medium">{task.title}</div>
      <TaskStatePill state={task.state} className="mt-1" />
    </div>
  )
}
