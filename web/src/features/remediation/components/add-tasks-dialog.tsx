'use client'

/**
 * Adds open tasks to a campaign. The list shows open tasks in no campaign;
 * "Include tasks in other campaigns" adds tasks that already have one, and
 * picking any of those moves it here (move: true). A task is in at most one
 * campaign: a 409 TASKS_IN_OTHER_CAMPAIGN lists the tasks and offers to move
 * the ones the caller may move.
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { ApiClientError } from '@/lib/api/error-handler'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import type { RemediationTask } from '@/features/remediation-hub/api/types'
import { useTasks } from '@/features/remediation-hub/api/use-remediation-hub'
import { useOwnerNames } from '@/features/remediation-hub/api/use-owner-names'
import { TaskStatePill } from '@/features/remediation-hub/components/task-bits'
import {
  type RemediationCampaign,
  type TaskInOtherCampaign,
  campaignApi,
  useRemediationCampaigns,
} from '../api/use-remediation-campaigns'

const OPEN_STATES = ['open', 'in_progress', 'verifying', 'on_hold'] as const

/** The tasks of a 409 TASKS_IN_OTHER_CAMPAIGN answer, or null for another error. */
export function tasksInOtherCampaign(err: unknown): TaskInOtherCampaign[] | null {
  if (!(err instanceof ApiClientError) || err.code !== 'TASKS_IN_OTHER_CAMPAIGN') return null
  const raw = (err.details as { tasks?: unknown } | undefined)?.tasks
  if (!Array.isArray(raw)) return []
  return raw
    .filter((x): x is Record<string, unknown> => !!x && typeof x === 'object')
    .map((x) => ({
      task_id: String(x.task_id ?? ''),
      campaign_id: String(x.campaign_id ?? ''),
      campaign_name: typeof x.campaign_name === 'string' ? x.campaign_name : null,
      can_move: x.can_move === true,
    }))
    .filter((x) => x.task_id)
}

export function AddTasksDialog({
  campaign,
  open,
  onOpenChange,
  onAdded,
}: {
  campaign: RemediationCampaign
  open: boolean
  onOpenChange: (open: boolean) => void
  onAdded: (c: RemediationCampaign) => void
}) {
  const { t } = useTranslation()
  const owners = useOwnerNames()
  const [search, setSearch] = useState('')
  const [includeOther, setIncludeOther] = useState(false)
  const [picked, setPicked] = useState<Map<string, RemediationTask>>(new Map())
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [conflicts, setConflicts] = useState<TaskInOtherCampaign[] | null>(null)

  useEffect(() => {
    if (!open) return
    setSearch('')
    setIncludeOther(false)
    setPicked(new Map())
    setError(null)
    setConflicts(null)
  }, [open])

  const { data, isLoading } = useTasks(
    {
      states: [...OPEN_STATES],
      search,
      sort: 'updated',
      perPage: 50,
      noCampaign: !includeOther,
    },
    open
  )
  const { data: others } = useRemediationCampaigns({ perPage: 100 }, open && includeOther)
  const campaignName = useMemo(
    () => new Map((others?.data ?? []).map((c) => [c.id, c.name])),
    [others]
  )
  const tasks = useMemo(
    () => (data?.data ?? []).filter((x) => x.campaign_id !== campaign.id),
    [data, campaign.id]
  )
  const ownerOf = useCallback(
    (task: RemediationTask) =>
      [owners.user(task.assignee_user_id), owners.group(task.assignee_group_id)]
        .filter(Boolean)
        .join(' · ') || t('remediationCampaigns.owner.unassigned'),
    [owners, t]
  )

  const toggle = (task: RemediationTask, on: boolean) =>
    setPicked((m) => {
      const next = new Map(m)
      if (on) next.set(task.id, task)
      else next.delete(task.id)
      return next
    })

  const send = async (ids: string[], move: boolean) => {
    setBusy(true)
    setError(null)
    try {
      const updated = await campaignApi.addTasks(campaign.id, {
        task_ids: ids,
        ...(move ? { move: true } : {}),
      })
      onAdded(updated)
      onOpenChange(false)
    } catch (err) {
      const found = tasksInOtherCampaign(err)
      if (found && found.length > 0) setConflicts(found)
      else
        setError(
          err instanceof ApiClientError && err.message
            ? err.message
            : t('remediationCampaigns.toast.failed')
        )
    } finally {
      setBusy(false)
    }
  }

  const ids = [...picked.keys()]
  const anyInOther = [...picked.values()].some((x) => !!x.campaign_id)
  const movable = conflicts?.filter((c) => c.can_move) ?? []
  const blocked = new Set((conflicts ?? []).filter((c) => !c.can_move).map((c) => c.task_id))

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>
            {conflicts
              ? t('remediationCampaigns.addTasks.conflictTitle')
              : t('remediationCampaigns.addTasks.title')}
          </DialogTitle>
          <DialogDescription>
            {conflicts
              ? t('remediationCampaigns.addTasks.conflictDescription')
              : t('remediationCampaigns.addTasks.description')}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-3">
          {conflicts ? (
            <ul className="divide-y rounded-md border" data-testid="tasks-in-other-campaign">
              {conflicts.map((c) => (
                <li key={c.task_id} className="p-3 text-sm">
                  <div className="font-medium">
                    {picked.get(c.task_id)?.title ?? t('remediationCampaigns.addTasks.aTask')}
                  </div>
                  <div className="text-muted-foreground text-xs">
                    {c.campaign_name
                      ? t('remediationCampaigns.addTasks.inCampaign', undefined, {
                          name: c.campaign_name,
                        })
                      : t('remediationCampaigns.addTasks.inHiddenCampaign')}
                    {!c.can_move && ` · ${t('remediationCampaigns.addTasks.cannotMove')}`}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <>
              <Input
                value={search}
                placeholder={t('remediationCampaigns.addTasks.search')}
                aria-label={t('remediationCampaigns.addTasks.search')}
                onChange={(e) => setSearch(e.target.value)}
              />
              <div className="flex items-center gap-2">
                <Switch
                  id="include-other-campaigns"
                  checked={includeOther}
                  onCheckedChange={setIncludeOther}
                />
                <Label htmlFor="include-other-campaigns" className="text-sm font-normal">
                  {t('remediationCampaigns.addTasks.includeOther')}
                </Label>
              </div>
              {isLoading && tasks.length === 0 ? (
                <div className="text-muted-foreground flex items-center gap-2 text-sm">
                  <Loader2 className="size-4 animate-spin" aria-hidden />
                  {t('remediationCampaigns.addTasks.loading')}
                </div>
              ) : tasks.length === 0 ? (
                <p className="text-muted-foreground text-sm">
                  {t('remediationCampaigns.addTasks.empty')}
                </p>
              ) : (
                <ul
                  className="divide-y rounded-md border"
                  aria-label={t('remediationCampaigns.addTasks.list')}
                >
                  {tasks.map((task) => {
                    const boxId = `add-task-${task.id}`
                    return (
                      <li key={task.id} className="flex items-start gap-3 p-3 text-sm">
                        <Checkbox
                          id={boxId}
                          className="mt-0.5"
                          checked={picked.has(task.id)}
                          onCheckedChange={(v) => toggle(task, v === true)}
                        />
                        <Label
                          htmlFor={boxId}
                          className="min-w-0 flex-1 cursor-pointer flex-col items-start gap-0.5 font-normal"
                        >
                          <span className="block truncate font-medium">{task.title}</span>
                          <span className="text-muted-foreground block text-xs">
                            {ownerOf(task)} ·{' '}
                            {t(
                              `remediationCampaigns.addTasks.findings.${task.counts.total === 1 ? 'one' : 'other'}`,
                              undefined,
                              { count: task.counts.total }
                            )}
                            {task.campaign_id &&
                              ` · ${
                                campaignName.get(task.campaign_id)
                                  ? t('remediationCampaigns.addTasks.inCampaign', undefined, {
                                      name: campaignName.get(task.campaign_id) ?? '',
                                    })
                                  : t('remediationCampaigns.addTasks.inOtherCampaign')
                              }`}
                          </span>
                        </Label>
                        <TaskStatePill state={task.state} />
                      </li>
                    )
                  })}
                </ul>
              )}
              {anyInOther && (
                <p className="text-muted-foreground text-xs">
                  {t('remediationCampaigns.addTasks.moveHint')}
                </p>
              )}
            </>
          )}
          {error && (
            <p role="alert" className="text-destructive text-sm">
              {error}
            </p>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            {t('remediationCampaigns.actions.cancel')}
          </Button>
          {conflicts ? (
            movable.length > 0 && (
              <Button
                onClick={() =>
                  void send(
                    ids.filter((id) => !blocked.has(id)),
                    true
                  )
                }
                disabled={busy}
              >
                {t(
                  `remediationCampaigns.addTasks.move.${movable.length === 1 ? 'one' : 'other'}`,
                  undefined,
                  { count: movable.length }
                )}
              </Button>
            )
          ) : (
            <Button onClick={() => void send(ids, anyInOther)} disabled={busy || ids.length === 0}>
              {busy && <Loader2 className="me-2 size-4 animate-spin" aria-hidden />}
              {t(
                `remediationCampaigns.addTasks.submit.${ids.length === 1 ? 'one' : 'other'}`,
                undefined,
                { count: ids.length }
              )}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
