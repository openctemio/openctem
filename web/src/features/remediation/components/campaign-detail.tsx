'use client'

/**
 * One campaign (/remediation/campaigns/[id]): its owner, due date and
 * progress, the tasks it holds, and the changes its status allows (start,
 * complete, reopen, cancel). Every change needs findings:remediation:write
 * and the campaign's can_edit (a restricted caller may change a campaign
 * only when every task of it is fully in their data scope); the API decides.
 */

import { useBreadcrumbTitle } from '@/components/layout'
import { useState } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { useRouter } from 'next/navigation'
import {
  ClipboardList,
  ExternalLink,
  EyeOff,
  Lock,
  MoreHorizontal,
  Pencil,
  Plus,
  Trash2,
  XCircle,
} from 'lucide-react'
import { toast } from 'sonner'
import { DetailPageHeader } from '@/features/shared/components/detail'
import { SafeExternalLink } from '@/components/safe-external-link'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { ApiClientError } from '@/lib/api/error-handler'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ActionMenu } from '@/components/ui/action-menu'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { StatusChip } from '@/features/shared/components/status-chip'
import { useTasks, useRevalidateHub } from '@/features/remediation-hub/api/use-remediation-hub'
import { useOwnerNames } from '@/features/remediation-hub/api/use-owner-names'
import { DataTable, RowNameLink } from '@/features/shared'
import {
  DeadlinePill,
  TaskProgressCell,
  TaskStatePill,
} from '@/features/remediation-hub/components/task-bits'
import type { RemediationTask } from '@/features/remediation-hub/api/types'
import {
  type RemediationCampaign,
  campaignApi,
  useRemediationCampaign,
  useRevalidateCampaigns,
} from '../api/use-remediation-campaigns'
import { CampaignDue } from './campaign-bits'
import { CampaignFormDialog } from './campaign-form-dialog'
import { CampaignStatusAction } from './campaign-status-action'
import { AddTasksDialog } from './add-tasks-dialog'
import { CreateJiraEpicDialog } from './create-jira-epic-dialog'

const TASK_PAGE = 25

/** Column widths (px) the room sums below are made of. */
const COL = { title: 220, state: 144, due: 144, actions: 48, progress: 160, owner: 150 } as const
const BASE_ROOM = COL.title + COL.state + COL.due + COL.actions
/**
 * The table-frame width (px) under which a column steps aside: the progress
 * first, then the owner. The running sum of the widths shown plus a margin,
 * so the row menu is never cut by the frame's scroller.
 */
const HIDE_BELOW = {
  progress: BASE_ROOM + COL.progress + 8,
  owner: BASE_ROOM + COL.progress + COL.owner + 8,
} as const

function errMessage(err: unknown, fallback: string) {
  return err instanceof ApiClientError && err.message ? err.message : fallback
}

export function CampaignDetail({ campaignId }: { campaignId: string }) {
  const { t } = useTranslation()
  const router = useRouter()
  const { hasPermission } = usePermissions()
  const canWrite = hasPermission(Permission.RemediationWrite)
  const owners = useOwnerNames()
  const revalidateCampaigns = useRevalidateCampaigns()
  const revalidateHub = useRevalidateHub()
  const { data: campaign, error, isLoading, mutate } = useRemediationCampaign(campaignId)
  useBreadcrumbTitle(campaign?.name)
  const [page, setPage] = useState(1)
  const {
    data: taskPage,
    isLoading: tasksLoading,
    mutate: mutateTasks,
  } = useTasks({ campaignId, sort: 'deadline', page, perPage: TASK_PAGE }, !!campaign)
  const [editOpen, setEditOpen] = useState(false)
  const [addOpen, setAddOpen] = useState(false)
  const [jiraOpen, setJiraOpen] = useState(false)
  const [confirm, setConfirm] = useState<'cancel' | 'delete' | null>(null)
  const [removeTask, setRemoveTask] = useState<RemediationTask | null>(null)
  const [busy, setBusy] = useState(false)

  if (error) {
    return (
      <ErrorState
        title={t('remediationCampaigns.detail.loadError')}
        error={error}
        onRetry={() => void mutate()}
      />
    )
  }
  if (isLoading || !campaign) {
    return (
      <div className="space-y-4" aria-busy="true">
        <Skeleton className="h-10 w-1/2" />
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    )
  }

  const c = campaign
  const s = c.summary
  const writable = canWrite && c.can_edit
  const open = c.status === 'draft' || c.status === 'active'
  const tasks = taskPage?.data ?? []
  const taskTotal = taskPage?.total ?? s.tasks
  const pages = Math.max(1, Math.ceil(taskTotal / TASK_PAGE))

  const applied = (next: RemediationCampaign) => {
    void mutate(next, { revalidate: false })
    void revalidateCampaigns()
  }
  const run = async (fn: () => Promise<unknown>, success: string) => {
    setBusy(true)
    try {
      const next = await fn()
      if (next && typeof next === 'object' && 'id' in next) applied(next as RemediationCampaign)
      else void revalidateCampaigns()
      void mutateTasks()
      void revalidateHub()
      toast.success(success)
      return true
    } catch (err) {
      if (err instanceof ApiClientError && err.statusCode === 409) void mutate()
      toast.error(errMessage(err, t('remediationCampaigns.toast.failed')))
      return false
    } finally {
      setBusy(false)
    }
  }
  const setStatus = (status: 'active' | 'completed' | 'canceled', success: string) =>
    run(() => campaignApi.setStatus(c.id, { status, version: c.version }), success)

  const ownerName = owners.user(c.assigned_to)
  const teamName = owners.group(c.assigned_team)
  const ownerOf = (task: RemediationTask) =>
    [owners.user(task.assignee_user_id), owners.group(task.assignee_group_id)]
      .filter(Boolean)
      .join(', ') || t('remediationCampaigns.owner.unassigned')

  const removeColumn: ColumnDef<RemediationTask> = {
    id: 'actions',
    header: '',
    enableSorting: false,
    meta: { kind: 'actions', width: COL.actions, label: t('components.col.actions', 'Actions') },
    cell: ({ row }: { row: { original: RemediationTask } }) => (
      <ActionMenu
        title={row.original.title}
        label={t('remediationCampaigns.detail.taskMenu', undefined, {
          task: row.original.title,
        })}
        items={[
          {
            id: 'remove-task',
            label: t('remediationCampaigns.actions.removeTask'),
            icon: XCircle,
            destructive: true,
            onSelect: () => setRemoveTask(row.original),
          },
        ]}
        trigger={
          <Button
            variant="ghost"
            size="icon"
            aria-label={t('remediationCampaigns.detail.taskMenu', undefined, {
              task: row.original.title,
            })}
          >
            <MoreHorizontal className="size-4" aria-hidden />
          </Button>
        }
      />
    ),
  }

  const taskColumns: ColumnDef<RemediationTask>[] = [
    {
      id: 'title',
      header: t('remediationHub.tasks.columns.task'),
      enableSorting: false,
      meta: { kind: 'name', label: t('remediationHub.tasks.columns.task') },
      cell: ({ row }) => (
        <RowNameLink
          href={`/remediation/tasks/${encodeURIComponent(row.original.id)}`}
          onOpen={() => router.push(`/remediation/tasks/${encodeURIComponent(row.original.id)}`)}
          title={row.original.title}
          className="block"
        >
          {row.original.title}
        </RowNameLink>
      ),
    },
    {
      id: 'owner',
      header: t('remediationHub.tasks.columns.owner'),
      enableSorting: false,
      meta: {
        kind: 'owner',
        label: t('remediationHub.tasks.columns.owner'),
        hideBelow: HIDE_BELOW.owner,
      },
      cell: ({ row }) => (
        <span className="block truncate text-sm" title={ownerOf(row.original)}>
          {ownerOf(row.original)}
        </span>
      ),
    },
    {
      id: 'state',
      header: t('remediationHub.tasks.columns.state'),
      enableSorting: false,
      meta: { kind: 'status', label: t('remediationHub.tasks.columns.state') },
      cell: ({ row }) => <TaskStatePill state={row.original.state} />,
    },
    {
      id: 'progress',
      header: t('remediationHub.tasks.columns.progress'),
      enableSorting: false,
      meta: {
        kind: 'text',
        label: t('remediationHub.tasks.columns.progress'),
        width: COL.progress,
        hideBelow: HIDE_BELOW.progress,
      },
      cell: ({ row }) => <TaskProgressCell task={row.original} />,
    },
    {
      id: 'deadline',
      header: t('remediationHub.tasks.columns.deadline'),
      enableSorting: false,
      meta: { kind: 'due', label: t('remediationHub.tasks.columns.deadline') },
      cell: ({ row }) => <DeadlinePill task={row.original} />,
    },
    ...(writable ? [removeColumn] : []),
  ]

  return (
    <div className="space-y-6">
      <DetailPageHeader
        title={c.name}
        parent={{
          href: '/remediation/campaigns',
          label: t('remediationCampaigns.detail.back'),
        }}
        chips={
          <>
            <StatusChip domain="remediationCampaign" value={c.status} />
            <span className="text-meta text-muted-foreground">
              {t(`remediationCampaigns.priority.${c.priority}`)}
            </span>
          </>
        }
        facts={
          <>
            {c.description && (
              <p className="text-muted-foreground basis-full text-sm break-words whitespace-pre-line">
                {c.description}
              </p>
            )}
            <dl className="text-muted-foreground flex basis-full flex-wrap items-center gap-x-4 gap-y-1 text-sm">
              <div className="flex gap-1">
                <dt className="after:content-[':']">{t('remediationCampaigns.detail.owner')}</dt>
                <dd className="text-foreground">
                  {ownerName ?? t('remediationCampaigns.owner.unassigned')}
                </dd>
              </div>
              {teamName && (
                <div className="flex gap-1">
                  <dt className="after:content-[':']">{t('remediationCampaigns.detail.team')}</dt>
                  <dd className="text-foreground">{teamName}</dd>
                </div>
              )}
              <div className="flex gap-1">
                <dt className="after:content-[':']">{t('remediationCampaigns.detail.due')}</dt>
                <dd className="text-foreground">
                  <CampaignDue campaign={c} relative />
                </dd>
              </div>
              {c.ticket && (
                <div className="flex gap-1">
                  <dt className="after:content-[':']">{t('remediationCampaigns.detail.jira')}</dt>
                  <dd>
                    <SafeExternalLink
                      href={c.ticket.issue_url}
                      className="text-foreground inline-flex items-center gap-1 underline"
                    >
                      {c.ticket.issue_key}
                      <ExternalLink className="size-3" aria-hidden />
                    </SafeExternalLink>
                  </dd>
                </div>
              )}
            </dl>
          </>
        }
        primary={
          writable ? (
            <CampaignStatusAction
              campaign={c}
              busy={busy}
              onSetStatus={(status, success) => void setStatus(status, success)}
            />
          ) : undefined
        }
        secondary={
          writable ? (
            <>
              {open && tasks.length > 0 && (
                <Button variant="outline" size="sm" onClick={() => setAddOpen(true)}>
                  <Plus className="size-4" aria-hidden />
                  {t('remediationCampaigns.actions.addTasks')}
                </Button>
              )}
              <Button variant="outline" size="sm" onClick={() => setEditOpen(true)}>
                <Pencil className="size-4" aria-hidden />
                {t('remediationCampaigns.actions.edit')}
              </Button>
            </>
          ) : undefined
        }
        menu={
          writable
            ? [
                ...(!c.ticket
                  ? [
                      {
                        id: 'create-epic',
                        label: t('remediationCampaigns.actions.createEpic'),
                        icon: ExternalLink,
                        onSelect: () => setJiraOpen(true),
                      },
                    ]
                  : []),
                ...(open
                  ? [
                      {
                        id: 'cancel',
                        label: t('remediationCampaigns.actions.cancelCampaign'),
                        icon: XCircle,
                        onSelect: () => setConfirm('cancel'),
                      },
                    ]
                  : []),
                {
                  id: 'delete',
                  label: t('remediationCampaigns.actions.delete'),
                  icon: Trash2,
                  destructive: true,
                  onSelect: () => setConfirm('delete'),
                },
              ]
            : undefined
        }
      />
      {canWrite && !c.can_edit && (
        <p
          className="flex items-center gap-2 text-sm text-muted-foreground"
          data-testid="campaign-read-only"
        >
          <Lock className="size-4" aria-hidden />
          {t('remediationCampaigns.detail.readOnly')}
        </p>
      )}

      <section className="space-y-3 rounded-lg border p-4" aria-labelledby="campaign-progress">
        <h2 className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 text-sm font-semibold">
          <span id="campaign-progress">{t('remediationCampaigns.detail.progress')}</span>
          {s.tasks === 0 ? (
            <span className="text-muted-foreground text-sm font-normal">
              {t('remediationCampaigns.detail.noProgress')}
            </span>
          ) : (
            <span className="text-sm font-normal">
              {s.findings > 0 &&
                t('remediationCampaigns.detail.findingsLine', undefined, {
                  closed: s.closed_findings,
                  total: s.findings,
                  pct: s.progress,
                  verified: s.verified_findings,
                })}
              {s.findings > 0 && ', '}
              {t(
                `remediationCampaigns.detail.tasksLine.${s.tasks === 1 ? 'one' : 'other'}`,
                undefined,
                {
                  count: s.tasks,
                  live: s.live_tasks,
                  done: s.done_tasks,
                }
              )}
              {s.overdue_tasks > 0 && (
                <span className="text-destructive">
                  {', '}
                  {t('remediationCampaigns.tasks.overdue', undefined, { count: s.overdue_tasks })}
                </span>
              )}
            </span>
          )}
        </h2>
        {s.tasks > 0 && s.findings > 0 && (
          <div
            role="progressbar"
            aria-label={t('remediationCampaigns.progress.label', undefined, {
              closed: s.closed_findings,
              total: s.findings,
            })}
            aria-valuemin={0}
            aria-valuemax={s.findings}
            aria-valuenow={Math.min(s.findings, s.closed_findings)}
            className="bg-muted flex h-1 w-full max-w-md overflow-hidden rounded-full"
          >
            <div
              className="bg-success h-full"
              style={{ width: `${Math.min(100, (s.closed_findings / s.findings) * 100)}%` }}
            />
          </div>
        )}
        {s.hidden_tasks > 0 && (
          <p
            className="flex items-center gap-2 text-sm text-warning"
            data-testid="campaign-hidden-tasks"
          >
            <EyeOff className="size-4" aria-hidden />
            {t(
              `remediationCampaigns.detail.hiddenTasks.${s.hidden_tasks === 1 ? 'one' : 'other'}`,
              undefined,
              { count: s.hidden_tasks }
            )}
          </p>
        )}
      </section>

      <section className="space-y-3" aria-labelledby="campaign-tasks">
        <div className="flex flex-wrap items-center gap-2">
          <h2 id="campaign-tasks" className="text-sm font-semibold">
            {t('remediationCampaigns.detail.tasks', undefined, { count: taskTotal })}
          </h2>
        </div>
        {!tasksLoading && tasks.length === 0 ? (
          <EmptyState
            icon={ClipboardList}
            title={t('remediationCampaigns.detail.emptyTitle')}
            description={t('remediationCampaigns.detail.emptyDescription')}
            action={
              writable && open ? (
                <Button onClick={() => setAddOpen(true)}>
                  <Plus className="size-4" aria-hidden />
                  {t('remediationCampaigns.actions.addTasks')}
                </Button>
              ) : undefined
            }
            card
          />
        ) : (
          <DataTable
            columns={taskColumns}
            data={tasks}
            caption={t('remediationCampaigns.detail.taskList')}
            isLoading={tasksLoading}
            manualPagination
            showSearch={false}
            showToolbar={false}
            rowCount={taskTotal}
            pageCount={pages}
            pagination={{ pageIndex: page - 1, pageSize: TASK_PAGE }}
            onPaginationChange={(next) => setPage(next.pageIndex + 1)}
            getRowId={(r) => r.id}
            onRowClick={(r) => router.push(`/remediation/tasks/${encodeURIComponent(r.id)}`)}
            paginationNoun={t('remediationHub.tasks.noun')}
          />
        )}
      </section>

      <CampaignFormDialog
        open={editOpen}
        onOpenChange={setEditOpen}
        campaign={c}
        onReload={() => void mutate()}
        onSubmit={async (fields) => {
          const next = await campaignApi.update(c.id, { ...fields, version: c.version })
          applied(next)
          toast.success(t('remediationCampaigns.toast.saved'))
        }}
      />
      <AddTasksDialog
        campaign={c}
        open={addOpen}
        onOpenChange={setAddOpen}
        onAdded={(next) => {
          applied(next)
          void mutateTasks()
          void revalidateHub()
          toast.success(t('remediationCampaigns.toast.tasksAdded'))
        }}
      />
      <CreateJiraEpicDialog
        campaign={jiraOpen ? { id: c.id, name: c.name } : null}
        onOpenChange={(o) => {
          setJiraOpen(o)
          if (!o) void mutate()
        }}
      />
      <ConfirmDialog
        open={confirm === 'cancel'}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={t('remediationCampaigns.confirm.cancelTitle', undefined, { name: c.name })}
        desc={t('remediationCampaigns.confirm.cancelDesc')}
        confirmText={t('remediationCampaigns.actions.cancelCampaign')}
        cancelBtnText={t('remediationCampaigns.actions.keep')}
        destructive
        isLoading={busy}
        handleConfirm={async () => {
          if (await setStatus('canceled', t('remediationCampaigns.toast.canceled')))
            setConfirm(null)
        }}
      />
      <ConfirmDialog
        open={confirm === 'delete'}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={t('remediationCampaigns.confirm.deleteTitle', undefined, { name: c.name })}
        desc={t('remediationCampaigns.confirm.deleteDesc')}
        confirmText={t('remediationCampaigns.actions.delete')}
        cancelBtnText={t('remediationCampaigns.actions.keep')}
        destructive
        isLoading={busy}
        handleConfirm={async () => {
          if (await run(() => campaignApi.remove(c.id), t('remediationCampaigns.toast.deleted'))) {
            setConfirm(null)
            router.push('/remediation/campaigns')
          }
        }}
      />
      <ConfirmDialog
        open={removeTask !== null}
        onOpenChange={(o) => !o && setRemoveTask(null)}
        title={t('remediationCampaigns.confirm.removeTaskTitle', undefined, {
          task: removeTask?.title ?? '',
        })}
        desc={t('remediationCampaigns.confirm.removeTaskDesc')}
        confirmText={t('remediationCampaigns.actions.removeTask')}
        cancelBtnText={t('remediationCampaigns.actions.keep')}
        isLoading={busy}
        handleConfirm={async () => {
          const task = removeTask
          if (!task) return
          if (
            await run(
              () => campaignApi.removeTask(c.id, task.id),
              t('remediationCampaigns.toast.taskRemoved')
            )
          )
            setRemoveTask(null)
        }}
      />
    </div>
  )
}
