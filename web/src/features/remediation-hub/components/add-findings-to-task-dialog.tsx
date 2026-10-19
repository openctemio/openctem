'use client'

/**
 * Adds findings from the findings list to remediation work: a new task
 * (title, owner, deadline, optionally a campaign) or an existing open task.
 * A finding is in at most one active task: when some already are, the API
 * answers 409 FINDINGS_IN_OTHER_TASK and the dialog shows them, to skip or,
 * where allowed, move with a reason (api/docs/rfcs/RFC-098-remediation-tasks.md).
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import useSWR from 'swr'
import { toast } from 'sonner'
import { Loader2 } from 'lucide-react'
import { get } from '@/lib/api/client'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { cn } from '@/lib/utils'
import type { ConflictResolution, FindingConflict, Page, RemediationTask } from '../api/types'
import { hubApi, useRevalidateHub, useTasks } from '../api/use-remediation-hub'
import { useOwnerNames } from '../api/use-owner-names'
import { claimConflicts } from '../lib/claim-conflicts'
import { ClaimConflictStep } from './claim-conflict-step'
import { apiMessage } from './suggestions-inbox'
import { TaskStatePill } from './task-bits'

export interface FindingRef {
  id: string
  title: string
}

const NONE = '__none__'
const OPEN_STATES = ['open', 'in_progress', 'verifying', 'on_hold'] as const

interface CampaignOption {
  id: string
  name: string
  status: string
}

/** Campaigns a task can join: draft or active, the first page by name. */
function useCampaignOptions(enabled: boolean) {
  const { data } = useSWR<Page<CampaignOption>>(
    enabled ? '/api/v1/remediation/campaigns?per_page=100' : null,
    get,
    { revalidateOnFocus: false }
  )
  return useMemo(
    () => (data?.data ?? []).filter((c) => c.status === 'draft' || c.status === 'active'),
    [data]
  )
}

type Mode = 'new' | 'existing'

export function AddFindingsToTaskDialog({
  open,
  onOpenChange,
  findings,
  onDone,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  findings: FindingRef[]
  onDone?: () => void
}) {
  const { t } = useTranslation()
  const router = useRouter()
  const owners = useOwnerNames()
  const revalidate = useRevalidateHub()
  const [mode, setMode] = useState<Mode>('new')
  const [title, setTitle] = useState('')
  const [user, setUser] = useState(NONE)
  const [group, setGroup] = useState(NONE)
  const [deadline, setDeadline] = useState('')
  const [campaign, setCampaign] = useState(NONE)
  const [search, setSearch] = useState('')
  const [target, setTarget] = useState<RemediationTask | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [conflicts, setConflicts] = useState<FindingConflict[] | null>(null)
  const [move, setMove] = useState<Set<string>>(new Set())
  const [reason, setReason] = useState('')

  const n = findings.length
  useEffect(() => {
    if (!open) return
    setMode('new')
    setTitle(
      n === 1 ? findings[0].title : t('remediationClaim.add.defaultTitle', undefined, { count: n })
    )
    setUser(NONE)
    setGroup(NONE)
    setDeadline('')
    setCampaign(NONE)
    setSearch('')
    setTarget(null)
    setError(null)
    setConflicts(null)
    setMove(new Set())
    setReason('')
    // Reset only when the dialog opens for a new selection.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const campaigns = useCampaignOptions(open)
  const { data: taskPage, isLoading: tasksLoading } = useTasks(
    { states: [...OPEN_STATES], search, sort: 'updated', perPage: 20 },
    open && mode === 'existing'
  )
  const titles = useMemo(() => new Map(findings.map((f) => [f.id, f.title])), [findings])
  const ownerOf = useCallback(
    (task: RemediationTask) =>
      [owners.user(task.assignee_user_id), owners.group(task.assignee_group_id)]
        .filter(Boolean)
        .join(' · ') || t('remediationClaim.conflict.unassigned'),
    [owners, t]
  )

  const submit = useCallback(
    async (resolution?: ConflictResolution) => {
      const ids = findings.map((f) => f.id)
      setBusy(true)
      setError(null)
      try {
        const task =
          mode === 'new'
            ? await hubApi.createTask({
                title: title.trim(),
                finding_ids: ids,
                ...(user !== NONE ? { assignee_user_id: user } : {}),
                ...(group !== NONE ? { assignee_group_id: group } : {}),
                ...(deadline ? { deadline } : {}),
                ...(campaign !== NONE ? { campaign_id: campaign } : {}),
                ...(resolution ? { conflicts: resolution } : {}),
              })
            : await hubApi.addMembers(target!.id, {
                version: target!.version,
                finding_ids: ids,
                ...(resolution ? { conflicts: resolution } : {}),
              })
        void revalidate()
        toast.success(
          mode === 'new'
            ? t('remediationClaim.toast.created', undefined, { task: task.title })
            : t('remediationClaim.toast.added', undefined, { task: task.title }),
          {
            action: {
              label: t('remediationClaim.toast.open'),
              onClick: () => router.push(`/remediation/tasks/${task.id}`),
            },
          }
        )
        onDone?.()
        onOpenChange(false)
      } catch (err) {
        const found = claimConflicts(err, titles)
        if (found && found.length > 0) {
          setConflicts(found)
          setMove(new Set())
          setReason('')
        } else {
          setError(apiMessage(err, t('remediationClaim.toast.failed')))
        }
      } finally {
        setBusy(false)
      }
    },
    [
      campaign,
      deadline,
      findings,
      group,
      mode,
      onDone,
      onOpenChange,
      revalidate,
      router,
      t,
      target,
      title,
      titles,
      user,
    ]
  )

  const canSubmit = mode === 'new' ? title.trim().length > 0 : target !== null
  const tasks = taskPage?.data ?? []

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>
            {conflicts
              ? t('remediationClaim.conflict.title')
              : t(`remediationClaim.add.title.${n === 1 ? 'one' : 'other'}`, undefined, {
                  count: n,
                })}
          </DialogTitle>
          <DialogDescription>
            {conflicts
              ? t('remediationClaim.conflict.description')
              : t('remediationClaim.add.description')}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          {conflicts ? (
            <ClaimConflictStep
              conflicts={conflicts}
              selected={move}
              onToggle={(id, on) =>
                setMove((s) => {
                  const next = new Set(s)
                  if (on) next.add(id)
                  else next.delete(id)
                  return next
                })
              }
              reason={reason}
              onReason={setReason}
            />
          ) : (
            <>
              <Tabs value={mode} onValueChange={(v) => setMode(v as Mode)}>
                <TabsList className="grid w-full grid-cols-2">
                  <TabsTrigger value="new">{t('remediationClaim.add.modeNew')}</TabsTrigger>
                  <TabsTrigger value="existing">
                    {t('remediationClaim.add.modeExisting')}
                  </TabsTrigger>
                </TabsList>
              </Tabs>
              {mode === 'new' ? (
                <div className="space-y-4">
                  <div className="space-y-1.5">
                    <Label htmlFor="add-task-title">{t('remediationClaim.add.taskTitle')}</Label>
                    <Input
                      id="add-task-title"
                      value={title}
                      maxLength={300}
                      onChange={(e) => setTitle(e.target.value)}
                    />
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label htmlFor="add-task-user">{t('remediationClaim.add.owner')}</Label>
                      <Select value={user} onValueChange={setUser}>
                        <SelectTrigger id="add-task-user">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value={NONE}>{t('remediationClaim.add.noOwner')}</SelectItem>
                          {owners.users.map((u) => (
                            <SelectItem key={u.id} value={u.id}>
                              {u.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="add-task-group">{t('remediationClaim.add.team')}</Label>
                      <Select value={group} onValueChange={setGroup}>
                        <SelectTrigger id="add-task-group">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value={NONE}>{t('remediationClaim.add.noTeam')}</SelectItem>
                          {owners.groups.map((g) => (
                            <SelectItem key={g.id} value={g.id}>
                              {g.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="add-task-deadline">
                        {t('remediationClaim.add.deadline')}
                      </Label>
                      <Input
                        id="add-task-deadline"
                        type="date"
                        value={deadline}
                        onChange={(e) => setDeadline(e.target.value)}
                      />
                    </div>
                    <div className="space-y-1.5">
                      <Label htmlFor="add-task-campaign">
                        {t('remediationClaim.add.campaign')}
                      </Label>
                      <Select value={campaign} onValueChange={setCampaign}>
                        <SelectTrigger id="add-task-campaign">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value={NONE}>
                            {t('remediationClaim.add.noCampaign')}
                          </SelectItem>
                          {campaigns.map((c) => (
                            <SelectItem key={c.id} value={c.id}>
                              {c.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  <Input
                    value={search}
                    placeholder={t('remediationClaim.add.searchTasks')}
                    aria-label={t('remediationClaim.add.searchTasks')}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                  {tasksLoading && tasks.length === 0 ? (
                    <div className="text-muted-foreground flex items-center gap-2 text-sm">
                      <Loader2 className="size-4 animate-spin" aria-hidden />
                      {t('remediationClaim.add.loadingTasks')}
                    </div>
                  ) : tasks.length === 0 ? (
                    <p className="text-muted-foreground text-sm">
                      {t('remediationClaim.add.noTasks')}
                    </p>
                  ) : (
                    <ul
                      role="listbox"
                      aria-label={t('remediationClaim.add.taskList')}
                      className="divide-y rounded-md border"
                    >
                      {tasks.map((task) => {
                        const selected = target?.id === task.id
                        return (
                          <li
                            key={task.id}
                            role="option"
                            aria-selected={selected}
                            tabIndex={0}
                            onClick={() => setTarget(task)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault()
                                setTarget(task)
                              }
                            }}
                            className={cn(
                              'hover:bg-muted/50 flex cursor-pointer flex-wrap items-center gap-2 p-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring',
                              selected && 'bg-muted'
                            )}
                          >
                            <div className="min-w-0 flex-1">
                              <div className="truncate font-medium">{task.title}</div>
                              <div className="text-muted-foreground text-xs">
                                {ownerOf(task)} ·{' '}
                                {t(
                                  `remediationClaim.add.findingCount.${task.counts.total === 1 ? 'one' : 'other'}`,
                                  undefined,
                                  { count: task.counts.total }
                                )}
                              </div>
                            </div>
                            <TaskStatePill state={task.state} />
                          </li>
                        )
                      })}
                    </ul>
                  )}
                </div>
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
          {conflicts ? (
            <>
              <Button variant="outline" onClick={() => setConflicts(null)} disabled={busy}>
                {t('remediationClaim.actions.back')}
              </Button>
              <Button variant="outline" onClick={() => void submit({ skip: true })} disabled={busy}>
                {t('remediationClaim.conflict.skip')}
              </Button>
              {conflicts.some((c) => c.can_move) && (
                <Button
                  onClick={() => void submit({ move: [...move], move_reason: reason.trim() })}
                  disabled={busy || move.size === 0 || !reason.trim()}
                >
                  {t('remediationClaim.conflict.move', undefined, { count: move.size })}
                </Button>
              )}
            </>
          ) : (
            <>
              <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
                {t('remediationClaim.actions.cancel')}
              </Button>
              <Button onClick={() => void submit()} disabled={busy || !canSubmit}>
                {busy && <Loader2 className="me-2 size-4 animate-spin" aria-hidden />}
                {mode === 'new'
                  ? t('remediationClaim.add.create')
                  : t('remediationClaim.add.addToTask')}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
