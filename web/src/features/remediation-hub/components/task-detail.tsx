'use client'

/**
 * One remediation task: what to do (fix steps), how far it is (verified,
 * closed, claimed, open), its findings grouped by asset (a windowed list
 * that loads as you scroll), and its timeline. Select findings to move them
 * (palette or drag onto a task of the same fix), split them off, or mark the
 * task fixed. Every change names the version it was based on; a move can be
 * undone from its toast.
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
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
  ArrowLeft,
  CheckCheck,
  EyeOff,
  GripVertical,
  MoreHorizontal,
  MoveRight,
  PauseCircle,
  PlayCircle,
  Scissors,
  XCircle,
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { ErrorState } from '@/features/shared/components/error-state'
import { RelativeTime } from '@/features/shared/components/relative-time'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import type { Severity } from '@/features/shared'
import { cn } from '@/lib/utils'
import {
  TERMINAL_TASK_STATES,
  type MarkFixedResult,
  type Page,
  type RemediationTask,
  type TaskMember,
} from '../api/types'
import {
  hubApi,
  memberPageUrl,
  useRevalidateHub,
  useTask,
  useTaskTimeline,
  useTasks,
} from '../api/use-remediation-hub'
import { useOwnerNames } from '../api/use-owner-names'
import { fixSteps, groupByAsset, isTypingTarget } from '../lib/hub'
import { FixStepsBlock } from './fix-steps'
import { MovePalette, type MoveTarget } from './move-palette'
import { apiMessage } from './suggestions-inbox'
import { CancelTaskDialog, MarkFixedDialog, SplitDialog } from './task-dialogs'
import { DeadlinePill, TaskCampaignLink, TaskProgress, TaskStatePill } from './task-bits'
import { useTaskException } from './task-exception'
import { TaskQueryPanel } from './task-query-panel'
import { VirtualRows } from './virtual-rows'

const MEMBER_PAGE = 200
const ROW_HEIGHT = 44

type Row =
  | { kind: 'group'; key: string; label: string; count: number }
  | { kind: 'member'; member: TaskMember }

export function TaskDetail({ taskId }: { taskId: string }) {
  const { t } = useTranslation()
  const { hasPermission } = usePermissions()
  const canWrite = hasPermission(Permission.RemediationWrite)
  const canFix = canWrite && hasPermission(Permission.FindingsFixApply)
  const owners = useOwnerNames()
  const revalidate = useRevalidateHub()
  const { data: task, error, isLoading, mutate } = useTask(taskId)
  const { data: timeline } = useTaskTimeline(taskId)
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
  const [fixOpen, setFixOpen] = useState(false)
  const [fixResult, setFixResult] = useState<MarkFixedResult | null>(null)
  const [cancelOpen, setCancelOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const { data: siblings } = useTasks(
    {
      actionId: task?.action_id,
      states: ['open', 'in_progress', 'verifying', 'on_hold'],
      perPage: 6,
    },
    !!task && canWrite
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

  const writable =
    !!task && canWrite && !TERMINAL_TASK_STATES.has(task.state) && task.hidden_members === 0
  const exception = useTaskException(taskId, writable)

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
    async (body: { title: string; assignee_user_id?: string; assignee_group_id?: string }) => {
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

  const doMarkFixed = useCallback(
    async (note: string) => {
      if (!task) return
      setBusy(true)
      try {
        const res = await hubApi.resolveTask(task.id, { version: task.version, note })
        setFixResult(res)
        await refresh()
      } catch (err) {
        toast.error(apiMessage(err, t('remediationHub.toast.failed')))
      } finally {
        setBusy(false)
      }
    },
    [refresh, t, task]
  )

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
        await refresh()
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
    [refresh, t, task]
  )

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (
        moveOpen ||
        splitOpen ||
        fixOpen ||
        cancelOpen ||
        exception.open ||
        e.metaKey ||
        e.ctrlKey ||
        e.altKey ||
        isTypingTarget(e.target)
      )
        return
      if (e.key === 'm' && writable && selected.size > 0) setMoveOpen(true)
      else if (
        e.key === 's' &&
        writable &&
        selected.size > 0 &&
        selected.size < (task?.counts.total ?? 0)
      )
        setSplitOpen(true)
      else if (e.key === 'f' && writable && canFix) {
        setFixResult(null)
        setFixOpen(true)
      } else return
      e.preventDefault()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [
    moveOpen,
    splitOpen,
    fixOpen,
    cancelOpen,
    exception.open,
    writable,
    canFix,
    selected.size,
    task,
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
      .join(' · ') || t('remediationHub.owner.unassigned')
  const steps = fixSteps(undefined, task.action_key)
  const targets = (siblings?.data ?? []).filter((x) => x.id !== task.id)

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start gap-3">
        <Button asChild variant="ghost" size="icon" aria-label={t('remediationHub.detail.back')}>
          <Link href="/remediation/tasks">
            <ArrowLeft className="size-4" aria-hidden />
          </Link>
        </Button>
        <div className="min-w-0 flex-1 basis-64">
          <h1 className="text-2xl font-bold tracking-tight break-words">{task.title}</h1>
          <p className="text-muted-foreground text-sm break-words">{task.action_title}</p>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-sm">
            <TaskStatePill state={task.state} />
            <DeadlinePill task={task} />
            <span className="text-muted-foreground">
              {t('remediationHub.detail.owner', undefined, { owner })}
            </span>
            <span className="text-muted-foreground" title={t('remediationHub.risk.explain')}>
              {t('remediationHub.detail.risk', undefined, { risk: task.counts.risk_points })}
            </span>
          </div>
          {task.state_note && (
            <p className="text-muted-foreground mt-1 text-xs">{task.state_note}</p>
          )}
          {task.archived_note && (
            <p className="text-muted-foreground mt-1 text-xs">{task.archived_note}</p>
          )}
          {task.regression_of && (
            <p className="mt-1 text-xs">
              <Link href={`/remediation/tasks/${task.regression_of}`} className="underline">
                {t('remediationHub.detail.regressionOf')}
              </Link>
            </p>
          )}
          {task.campaign_id && <TaskCampaignLink campaignId={task.campaign_id} />}
        </div>
        {writable && (
          <div className="flex flex-wrap items-center gap-2">
            {exception.action}
            {canFix && (
              <Button
                onClick={() => {
                  setFixResult(null)
                  setFixOpen(true)
                }}
                aria-keyshortcuts="f"
              >
                <CheckCheck className="size-4" aria-hidden />
                {t('remediationHub.detail.markFixed')}
              </Button>
            )}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="icon" aria-label={t('remediationHub.detail.more')}>
                  <MoreHorizontal className="size-4" aria-hidden />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {task.state === 'on_hold' ? (
                  <DropdownMenuItem onSelect={() => void setHold(false)}>
                    <PlayCircle className="size-4" aria-hidden />
                    {t('remediationHub.detail.resume')}
                  </DropdownMenuItem>
                ) : (
                  <DropdownMenuItem onSelect={() => void setHold(true)}>
                    <PauseCircle className="size-4" aria-hidden />
                    {t('remediationHub.detail.hold')}
                  </DropdownMenuItem>
                )}
                <DropdownMenuItem onSelect={() => setCancelOpen(true)} className="text-destructive">
                  <XCircle className="size-4" aria-hidden />
                  {t('remediationHub.detail.cancel')}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        )}
      </div>

      {exception.banner}

      {task.hidden_members > 0 && (
        <p className="flex items-center gap-2 text-sm text-warning">
          <EyeOff className="size-4" aria-hidden />
          {t('remediationHub.detail.hidden', undefined, { n: task.hidden_members })}
        </p>
      )}

      <TaskQueryPanel taskId={task.id} writable={writable} onChanged={() => void mutate()} />

      <section className="grid gap-4 lg:grid-cols-[2fr_1fr]">
        <div className="space-y-2 rounded-lg border p-4">
          <h2 className="text-sm font-semibold">{t('remediationHub.detail.fix')}</h2>
          <FixStepsBlock steps={steps} />
        </div>
        <div className="space-y-2 rounded-lg border p-4">
          <h2 className="text-sm font-semibold">{t('remediationHub.detail.progress')}</h2>
          <TaskProgress task={task} />
          <dl className="grid grid-cols-2 gap-1 text-sm">
            {(['verified', 'closed', 'fix_applied', 'in_progress', 'open'] as const).map((k) => (
              <div key={k} className="contents">
                <dt className="text-muted-foreground">{t(`remediationHub.detail.count.${k}`)}</dt>
                <dd className="text-end font-mono">{task.counts[k]}</dd>
              </div>
            ))}
          </dl>
          <p className="text-muted-foreground text-xs">{t('remediationHub.detail.doneRule')}</p>
        </div>
      </section>

      <DndContext sensors={sensors} onDragEnd={onDragEnd}>
        <section className="grid gap-4 lg:grid-cols-[1fr_16rem]">
          <div className="rounded-lg border">
            <div className="flex flex-wrap items-center gap-2 border-b p-3">
              <h2 className="text-sm font-semibold">
                {t('remediationHub.detail.findings', undefined, { n: totalMembers })}
              </h2>
              {writable && selected.size > 0 && (
                <div className="ms-auto flex flex-wrap items-center gap-2">
                  <span className="text-muted-foreground text-xs">
                    {t('remediationHub.detail.selected', undefined, { n: selected.size })}
                  </span>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setMoveOpen(true)}
                    aria-keyshortcuts="m"
                  >
                    <MoveRight className="size-4" aria-hidden />
                    {t('remediationHub.detail.moveTo')}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setSplitOpen(true)}
                    disabled={selected.size >= task.counts.total}
                    aria-keyshortcuts="s"
                  >
                    <Scissors className="size-4" aria-hidden />
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
                rowHeight={ROW_HEIGHT}
                height={480}
                label={t('remediationHub.detail.findingsList')}
                rowKey={(r) => (r.kind === 'group' ? `g:${r.key}` : r.member.finding_id)}
                onEndReached={() => {
                  if (loaded.length < totalMembers && !members.isValidating)
                    void members.setSize(members.size + 1)
                }}
                renderRow={(r) =>
                  r.kind === 'group' ? (
                    <div className="bg-muted/50 flex h-full items-center justify-between px-3 text-xs font-medium">
                      <span className="truncate">{r.label}</span>
                      <span className="text-muted-foreground">{r.count}</span>
                    </div>
                  ) : (
                    <MemberRow
                      member={r.member}
                      selectable={writable}
                      selected={selected.has(r.member.finding_id)}
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
          </div>
          {writable && targets.length > 0 && (
            <aside className="space-y-2" aria-label={t('remediationHub.detail.dropTargets')}>
              <h2 className="text-sm font-semibold">{t('remediationHub.detail.dropTargets')}</h2>
              <p className="text-muted-foreground text-xs">{t('remediationHub.detail.dropHint')}</p>
              {targets.map((x) => (
                <DropTask key={x.id} task={x} />
              ))}
            </aside>
          )}
        </section>
      </DndContext>

      <section className="rounded-lg border p-4">
        <h2 className="mb-3 text-sm font-semibold">{t('remediationHub.detail.timeline')}</h2>
        {(timeline?.data ?? []).length === 0 ? (
          <p className="text-muted-foreground text-sm">{t('remediationHub.detail.noEvents')}</p>
        ) : (
          <ol className="space-y-2">
            {(timeline?.data ?? []).map((e) => (
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
        open={splitOpen}
        onOpenChange={setSplitOpen}
        onConfirm={(body) => void doSplit(body)}
        busy={busy}
      />
      <MarkFixedDialog
        task={task}
        open={fixOpen}
        onOpenChange={setFixOpen}
        onConfirm={(note) => void doMarkFixed(note)}
        busy={busy}
        result={fixResult}
      />
      {exception.dialog}
      <CancelTaskDialog
        open={cancelOpen}
        onOpenChange={setCancelOpen}
        onConfirm={(note) => void setHold(null, note)}
        busy={busy}
      />
    </div>
  )
}

function MemberRow({
  member: m,
  selectable,
  selected,
  onSelect,
}: {
  member: TaskMember
  selectable: boolean
  selected: boolean
  onSelect: (v: boolean) => void
}) {
  const { t } = useTranslation()
  const { attributes, listeners, setNodeRef, transform, isDragging } = useDraggable({
    id: m.finding_id,
    disabled: !selectable || m.role !== 'primary',
  })
  const style = transform
    ? { transform: `translate3d(${transform.x}px, ${transform.y}px, 0)` }
    : undefined
  return (
    <div
      ref={setNodeRef}
      style={style}
      className={cn(
        'flex h-full items-center gap-2 border-b px-3 text-sm',
        isDragging && 'bg-muted opacity-70'
      )}
    >
      {selectable && m.role === 'primary' && (
        <>
          <button
            type="button"
            className="text-muted-foreground cursor-grab"
            aria-label={t('remediationHub.detail.drag', undefined, { title: m.title })}
            {...listeners}
            {...attributes}
          >
            <GripVertical className="size-4" aria-hidden />
          </button>
          <Checkbox
            checked={selected}
            onCheckedChange={(v) => onSelect(v === true)}
            aria-label={t('remediationHub.detail.selectFinding', undefined, { title: m.title })}
          />
        </>
      )}
      <SeverityBadge severity={m.severity as Severity} />
      <Link href={`/findings/${m.finding_id}`} className="min-w-0 flex-1 truncate hover:underline">
        {m.title}
      </Link>
      {m.role === 'related' && (
        <span className="text-muted-foreground text-xs">{t('remediationHub.detail.related')}</span>
      )}
      <span className="text-muted-foreground hidden text-xs sm:inline">
        {t(`remediationHub.findingStatus.${m.status}`, m.status)}
      </span>
      {m.verified && (
        <CheckCheck
          className="size-4 text-success"
          aria-label={t('remediationHub.detail.verified')}
        />
      )}
    </div>
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
