'use client'

/**
 * One campaign (/remediation/campaigns/[id]): its owner, due date and
 * progress, the tasks it holds, and the changes its status allows (start,
 * complete, reopen, cancel). Every change needs findings:remediation:write
 * and the campaign's can_edit (a restricted caller may change a campaign
 * only when every task of it is fully in their data scope); the API decides.
 */

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import {
  ArrowLeft,
  CheckCheck,
  ClipboardList,
  ExternalLink,
  EyeOff,
  Lock,
  MoreHorizontal,
  Pencil,
  Play,
  Plus,
  RotateCcw,
  Trash2,
  XCircle,
} from 'lucide-react'
import { toast } from 'sonner'
import Link from '@/components/link'
import { SafeExternalLink } from '@/components/safe-external-link'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { usePermissions } from '@/context/permission-provider'
import { Permission } from '@/lib/permissions'
import { ApiClientError } from '@/lib/api/error-handler'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { EmptyState } from '@/features/shared/components/empty-state'
import { ErrorState } from '@/features/shared/components/error-state'
import { StatusChip } from '@/features/shared/components/status-chip'
import { useTasks, useRevalidateHub } from '@/features/remediation-hub/api/use-remediation-hub'
import { useOwnerNames } from '@/features/remediation-hub/api/use-owner-names'
import { TaskCard } from '@/features/remediation-hub/components/tasks-view'
import type { RemediationTask } from '@/features/remediation-hub/api/types'
import {
  type RemediationCampaign,
  campaignApi,
  useRemediationCampaign,
  useRevalidateCampaigns,
} from '../api/use-remediation-campaigns'
import { CampaignDue, FindingsProgress } from './campaign-bits'
import { CampaignFormDialog } from './campaign-form-dialog'
import { AddTasksDialog } from './add-tasks-dialog'
import { CreateJiraEpicDialog } from './create-jira-epic-dialog'

const TASK_PAGE = 25

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
      .join(' · ') || t('remediationCampaigns.owner.unassigned')

  const completeBlocked = s.live_tasks > 0
  const completeReason = t(
    `remediationCampaigns.detail.completeBlocked.${s.live_tasks === 1 ? 'one' : 'other'}`,
    undefined,
    { count: s.live_tasks }
  )

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start gap-3">
        <Button
          asChild
          variant="ghost"
          size="icon"
          aria-label={t('remediationCampaigns.detail.back')}
        >
          <Link href="/remediation/campaigns">
            <ArrowLeft className="size-4" aria-hidden />
          </Link>
        </Button>
        <div className="min-w-0 flex-1 basis-64">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight break-words">{c.name}</h1>
            <StatusChip domain="remediationCampaign" value={c.status} />
          </div>
          {c.description && (
            <p className="text-muted-foreground mt-1 text-sm break-words whitespace-pre-line">
              {c.description}
            </p>
          )}
          <dl className="text-muted-foreground mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
            <div className="flex gap-1">
              <dt>{t('remediationCampaigns.detail.owner')}</dt>
              <dd className="text-foreground">
                {ownerName ?? t('remediationCampaigns.owner.unassigned')}
              </dd>
            </div>
            {teamName && (
              <div className="flex gap-1">
                <dt>{t('remediationCampaigns.detail.team')}</dt>
                <dd className="text-foreground">{teamName}</dd>
              </div>
            )}
            <div className="flex gap-1">
              <dt>{t('remediationCampaigns.detail.due')}</dt>
              <dd className="text-foreground">
                <CampaignDue campaign={c} relative />
              </dd>
            </div>
            <div className="flex gap-1">
              <dt>{t('remediationCampaigns.detail.priority')}</dt>
              <dd className="text-foreground">
                {t(`remediationCampaigns.priority.${c.priority}`)}
              </dd>
            </div>
            {c.ticket && (
              <div className="flex gap-1">
                <dt>{t('remediationCampaigns.detail.jira')}</dt>
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
        </div>
        {writable && (
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" onClick={() => setEditOpen(true)}>
              <Pencil className="size-4" aria-hidden />
              {t('remediationCampaigns.actions.edit')}
            </Button>
            {c.status === 'draft' && (
              <Button
                disabled={busy}
                onClick={() => void setStatus('active', t('remediationCampaigns.toast.started'))}
              >
                <Play className="size-4" aria-hidden />
                {t('remediationCampaigns.actions.start')}
              </Button>
            )}
            {c.status === 'active' &&
              (completeBlocked ? (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span tabIndex={0} aria-describedby="complete-blocked-reason">
                      <Button disabled aria-disabled>
                        <CheckCheck className="size-4" aria-hidden />
                        {t('remediationCampaigns.actions.complete')}
                      </Button>
                    </span>
                  </TooltipTrigger>
                  <TooltipContent id="complete-blocked-reason">{completeReason}</TooltipContent>
                </Tooltip>
              ) : (
                <Button
                  disabled={busy}
                  onClick={() =>
                    void setStatus('completed', t('remediationCampaigns.toast.completed'))
                  }
                >
                  <CheckCheck className="size-4" aria-hidden />
                  {t('remediationCampaigns.actions.complete')}
                </Button>
              ))}
            {c.status === 'completed' && (
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => void setStatus('active', t('remediationCampaigns.toast.reopened'))}
              >
                <RotateCcw className="size-4" aria-hidden />
                {t('remediationCampaigns.actions.reopen')}
              </Button>
            )}
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="icon"
                  aria-label={t('remediationCampaigns.actions.more')}
                >
                  <MoreHorizontal className="size-4" aria-hidden />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {!c.ticket && (
                  <DropdownMenuItem onSelect={() => setJiraOpen(true)}>
                    <ExternalLink className="size-4" aria-hidden />
                    {t('remediationCampaigns.actions.createEpic')}
                  </DropdownMenuItem>
                )}
                {open && (
                  <DropdownMenuItem onSelect={() => setConfirm('cancel')}>
                    <XCircle className="size-4" aria-hidden />
                    {t('remediationCampaigns.actions.cancelCampaign')}
                  </DropdownMenuItem>
                )}
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onSelect={() => setConfirm('delete')}
                  className="text-destructive"
                >
                  <Trash2 className="size-4" aria-hidden />
                  {t('remediationCampaigns.actions.delete')}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        )}
      </div>

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
        <h2 id="campaign-progress" className="text-sm font-semibold">
          {t('remediationCampaigns.detail.progress')}
        </h2>
        {s.tasks === 0 ? (
          <p className="text-muted-foreground text-sm">
            {t('remediationCampaigns.detail.noProgress')}
          </p>
        ) : (
          <>
            <FindingsProgress
              summary={s}
              className="[&>div[role=progressbar]]:w-full [&>div[role=progressbar]]:max-w-md"
            />
            <p className="text-sm">
              {s.findings > 0 &&
                t('remediationCampaigns.detail.findingsLine', undefined, {
                  closed: s.closed_findings,
                  total: s.findings,
                  pct: s.progress,
                  verified: s.verified_findings,
                })}
              {s.findings > 0 && ' · '}
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
                  {' · '}
                  {t('remediationCampaigns.tasks.overdue', undefined, { count: s.overdue_tasks })}
                </span>
              )}
            </p>
          </>
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
          {writable && open && tasks.length > 0 && (
            <Button
              size="sm"
              variant="outline"
              className="ms-auto"
              onClick={() => setAddOpen(true)}
            >
              <Plus className="size-4" aria-hidden />
              {t('remediationCampaigns.actions.addTasks')}
            </Button>
          )}
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
          <ul
            className="grid gap-2 md:grid-cols-2"
            aria-label={t('remediationCampaigns.detail.taskList')}
          >
            {tasks.map((task) => (
              <li key={task.id} className="relative">
                <TaskCard
                  task={task}
                  owner={ownerOf(task)}
                  className={writable ? 'pe-12' : undefined}
                />
                {writable && (
                  <div className="absolute end-2 top-2">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8"
                          aria-label={t('remediationCampaigns.detail.taskMenu', undefined, {
                            task: task.title,
                          })}
                        >
                          <MoreHorizontal className="size-4" aria-hidden />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onSelect={() => setRemoveTask(task)}>
                          <XCircle className="size-4" aria-hidden />
                          {t('remediationCampaigns.actions.removeTask')}
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
        {pages > 1 && (
          <div className="flex items-center justify-end gap-2 text-sm">
            <Button
              size="sm"
              variant="outline"
              disabled={page <= 1}
              onClick={() => setPage(page - 1)}
            >
              {t('remediationCampaigns.pager.previous')}
            </Button>
            <span className="text-muted-foreground">
              {t('remediationCampaigns.pager.page', undefined, { page, pages })}
            </span>
            <Button
              size="sm"
              variant="outline"
              disabled={page >= pages}
              onClick={() => setPage(page + 1)}
            >
              {t('remediationCampaigns.pager.next')}
            </Button>
          </div>
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
