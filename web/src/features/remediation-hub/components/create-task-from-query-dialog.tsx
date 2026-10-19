'use client'

/**
 * Creates a remediation task from a query (api/docs/rfcs/RFC-098-remediation-tasks.md,
 * "Tasks from a query"). The person writes or opens a "findings where ..."
 * query, previews what it selects in their own access (count, breakdowns,
 * a sample, matches other tasks hold, the earliest SLA deadline and a
 * suggested owner), then creates the task as a snapshot or with auto include.
 * Findings another active task holds are skipped unless the person moves
 * them, with a reason, out of a task they may change.
 */

import { useCallback, useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { toast } from 'sonner'
import { Loader2 } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
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
import type { ConflictResolution } from '../api/types'
import { useRevalidateHub } from '../api/use-remediation-hub'
import { useOwnerNames } from '../api/use-owner-names'
import {
  MAX_QUERY_TASK_FINDINGS,
  taskQueryApi,
  type QueryMode,
  type QueryTaskPreview,
} from '../api/use-task-query'
import { claimConflicts } from '../lib/claim-conflicts'
import { ClaimConflictStep } from './claim-conflict-step'
import { QueryBox } from './query-box'
import { QueryPreviewPanel } from './query-preview-panel'
import { apiMessage } from './suggestions-inbox'

const NONE = '__none__'
export const DEFAULT_TASK_QUERY = 'findings where severity in (critical, high)'

export function CreateTaskFromQueryDialog({
  open,
  onOpenChange,
  initialQuery,
  ignoredFilters,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** A query to start from (the findings list's filters, as text). */
  initialQuery?: string
  /** List params that could not be carried into the query. */
  ignoredFilters?: string[]
}) {
  const { t } = useTranslation()
  const router = useRouter()
  const owners = useOwnerNames()
  const revalidate = useRevalidateHub()
  const [query, setQuery] = useState('')
  const [preview, setPreview] = useState<QueryTaskPreview | null>(null)
  const [previewedText, setPreviewedText] = useState('')
  const [title, setTitle] = useState('')
  const [user, setUser] = useState(NONE)
  const [group, setGroup] = useState(NONE)
  const [deadline, setDeadline] = useState('')
  const [mode, setMode] = useState<QueryMode>('snapshot')
  const [cap, setCap] = useState(String(MAX_QUERY_TASK_FINDINGS))
  const [move, setMove] = useState<Set<string>>(new Set())
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState<'preview' | 'create' | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    setQuery(initialQuery?.trim() || DEFAULT_TASK_QUERY)
    setPreview(null)
    setPreviewedText('')
    setTitle('')
    setUser(NONE)
    setGroup(NONE)
    setDeadline('')
    setMode('snapshot')
    setCap(String(MAX_QUERY_TASK_FINDINGS))
    setMove(new Set())
    setReason('')
    setError(null)
    // Reset only when the dialog opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const runPreview = useCallback(async () => {
    setBusy('preview')
    setError(null)
    try {
      const p = await taskQueryApi.preview(query)
      setPreview(p)
      setPreviewedText(query)
      setMove(new Set())
      setReason('')
      if (!title.trim()) setTitle(t('remediationQuery.create.defaultTitle'))
      const s = p.suggested_assignee
      if (s?.user_id && user === NONE) setUser(s.user_id)
      else if (s?.group_id && group === NONE) setGroup(s.group_id)
    } catch (err) {
      setPreview(null)
      setError(apiMessage(err, t('remediationQuery.create.previewFailed')))
    } finally {
      setBusy(null)
    }
  }, [group, query, t, title, user])

  const stale = preview !== null && previewedText !== query
  const capN = Number(cap)
  const capValid =
    mode === 'snapshot' || (Number.isInteger(capN) && capN >= 1 && capN <= MAX_QUERY_TASK_FINDINGS)
  const moveNeedsReason = move.size > 0 && reason.trim().length === 0
  const canCreate =
    preview !== null &&
    !stale &&
    !preview.too_many &&
    preview.total > 0 &&
    (preview.claimable > 0 || move.size > 0) &&
    title.trim().length > 0 &&
    capValid &&
    !moveNeedsReason

  const create = useCallback(async () => {
    if (!preview) return
    setBusy('create')
    setError(null)
    let conflicts: ConflictResolution | undefined
    if (preview.conflicts.length > 0) {
      conflicts = move.size > 0 ? { move: [...move], move_reason: reason.trim() } : { skip: true }
    }
    try {
      const res = await taskQueryApi.create({
        title: title.trim(),
        query,
        mode,
        ...(mode === 'auto' ? { cap: capN } : {}),
        ...(user !== NONE ? { assignee_user_id: user } : {}),
        ...(group !== NONE ? { assignee_group_id: group } : {}),
        ...(deadline ? { deadline } : {}),
        ...(conflicts ? { conflicts } : {}),
      })
      void revalidate()
      toast.success(
        t('remediationQuery.create.created', undefined, {
          task: res.task.title,
          count: res.added + res.moved,
        }),
        {
          action: {
            label: t('remediationQuery.create.open'),
            onClick: () => router.push(`/remediation/tasks/${res.task.id}`),
          },
        }
      )
      onOpenChange(false)
      router.push(`/remediation/tasks/${res.task.id}`)
    } catch (err) {
      const found = claimConflicts(err)
      if (found && found.length > 0) {
        // Someone claimed a match since the preview: show the conflicts as
        // they are now and let the person decide again.
        setPreview({
          ...preview,
          conflicts: found,
          claimable: Math.max(0, preview.total - found.length),
        })
        setMove(new Set())
        setError(t('remediationQuery.create.conflictsChanged'))
      } else {
        setError(apiMessage(err, t('remediationQuery.create.failed')))
      }
    } finally {
      setBusy(null)
    }
  }, [
    capN,
    deadline,
    group,
    mode,
    move,
    onOpenChange,
    preview,
    query,
    reason,
    revalidate,
    router,
    t,
    title,
    user,
  ])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="xl">
        <DialogHeader>
          <DialogTitle>{t('remediationQuery.create.title')}</DialogTitle>
          <DialogDescription>{t('remediationQuery.create.description')}</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-5">
          <div className="space-y-1.5">
            <Label htmlFor="task-query">{t('remediationQuery.create.queryLabel')}</Label>
            <QueryBox id="task-query" value={query} onChange={setQuery} autoFocus />
            {ignoredFilters && ignoredFilters.length > 0 && (
              <p className="text-xs text-amber-600 dark:text-amber-400">
                {t('remediationQuery.create.ignoredFilters', undefined, {
                  filters: ignoredFilters.join(', '),
                })}
              </p>
            )}
            <div className="flex flex-wrap items-center gap-2">
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={runPreview}
                disabled={busy !== null || query.trim().length === 0}
              >
                {busy === 'preview' && (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />
                )}
                {preview
                  ? t('remediationQuery.create.previewAgain')
                  : t('remediationQuery.create.preview')}
              </Button>
              {stale && (
                <span className="text-muted-foreground text-xs">
                  {t('remediationQuery.create.stale')}
                </span>
              )}
            </div>
          </div>

          {preview && <QueryPreviewPanel preview={preview} ownerName={owners} />}

          {preview && !preview.too_many && preview.conflicts.length > 0 && (
            <ClaimConflictStep
              conflicts={preview.conflicts}
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
          )}

          {preview && !preview.too_many && preview.total > 0 && (
            <div className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="query-task-title">{t('remediationQuery.create.taskTitle')}</Label>
                <Input
                  id="query-task-title"
                  value={title}
                  maxLength={300}
                  onChange={(e) => setTitle(e.target.value)}
                />
              </div>
              <div className="grid gap-4 sm:grid-cols-3">
                <div className="space-y-1.5">
                  <Label htmlFor="query-task-user">{t('remediationQuery.create.owner')}</Label>
                  <Select value={user} onValueChange={setUser}>
                    <SelectTrigger id="query-task-user">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NONE}>{t('remediationQuery.create.noOwner')}</SelectItem>
                      {owners.users.map((u) => (
                        <SelectItem key={u.id} value={u.id}>
                          {u.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="query-task-group">{t('remediationQuery.create.team')}</Label>
                  <Select value={group} onValueChange={setGroup}>
                    <SelectTrigger id="query-task-group">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NONE}>{t('remediationQuery.create.noTeam')}</SelectItem>
                      {owners.groups.map((g) => (
                        <SelectItem key={g.id} value={g.id}>
                          {g.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="query-task-deadline">
                    {t('remediationQuery.create.deadline')}
                  </Label>
                  <Input
                    id="query-task-deadline"
                    type="date"
                    value={deadline}
                    onChange={(e) => setDeadline(e.target.value)}
                  />
                </div>
              </div>
              <fieldset className="space-y-2">
                <legend className="text-sm font-medium">{t('remediationQuery.mode.label')}</legend>
                <RadioGroup
                  value={mode}
                  onValueChange={(v) => setMode(v as QueryMode)}
                  className="gap-3"
                >
                  <label className="flex items-start gap-3 rounded-md border p-3 text-sm">
                    <RadioGroupItem value="snapshot" id="query-mode-snapshot" className="mt-0.5" />
                    <span>
                      <span className="font-medium">{t('remediationQuery.mode.snapshot')}</span>
                      <span className="text-muted-foreground block text-xs">
                        {t('remediationQuery.mode.snapshotHelp')}
                      </span>
                    </span>
                  </label>
                  <label className="flex items-start gap-3 rounded-md border p-3 text-sm">
                    <RadioGroupItem value="auto" id="query-mode-auto" className="mt-0.5" />
                    <span>
                      <span className="font-medium">{t('remediationQuery.mode.auto')}</span>
                      <span className="text-muted-foreground block text-xs">
                        {t('remediationQuery.mode.autoHelp')}
                      </span>
                    </span>
                  </label>
                </RadioGroup>
                {mode === 'auto' && (
                  <div className="space-y-2 rounded-md bg-muted/50 p-3 text-xs">
                    <ul className="list-disc space-y-1 pl-4">
                      <li>{t('remediationQuery.mode.guardUnclaimed')}</li>
                      <li>{t('remediationQuery.mode.guardScope')}</li>
                      <li>{t('remediationQuery.mode.guardSuspend')}</li>
                      <li>{t('remediationQuery.mode.guardNotify')}</li>
                    </ul>
                    <div className="flex items-center gap-2 pt-1">
                      <Label htmlFor="query-task-cap" className="text-xs">
                        {t('remediationQuery.mode.cap')}
                      </Label>
                      <Input
                        id="query-task-cap"
                        type="number"
                        min={1}
                        max={MAX_QUERY_TASK_FINDINGS}
                        value={cap}
                        className="h-8 w-28"
                        aria-invalid={!capValid}
                        onChange={(e) => setCap(e.target.value)}
                      />
                    </div>
                  </div>
                )}
              </fieldset>
            </div>
          )}

          {error && (
            <p role="alert" className="text-destructive text-sm">
              {error}
            </p>
          )}
        </DialogBody>
        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={busy === 'create'}
          >
            {t('remediationQuery.create.cancel')}
          </Button>
          <Button onClick={create} disabled={!canCreate || busy !== null}>
            {busy === 'create' && <Loader2 className="mr-2 h-4 w-4 animate-spin" aria-hidden />}
            {t('remediationQuery.create.submit')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
