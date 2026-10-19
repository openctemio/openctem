'use client'

/**
 * "Created from query" on a task's page: the stored query (plain text), its
 * mode, and for auto include its state (active, paused, or suspended with
 * the reason). "Re-run" shows the new matches no other task holds and adds
 * them only when the person confirms. Renders nothing for a task that was
 * not created from a query.
 */

import { useCallback, useState } from 'react'
import { toast } from 'sonner'
import { Loader2, PauseCircle, PlayCircle, RefreshCw } from 'lucide-react'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { useOwnerNames } from '../api/use-owner-names'
import { taskQueryApi, useTaskQuery, type QueryRerunPreview } from '../api/use-task-query'
import { apiMessage } from './suggestions-inbox'

export function TaskQueryPanel({
  taskId,
  writable,
  onChanged,
}: {
  taskId: string
  writable: boolean
  onChanged?: () => void
}) {
  const { t } = useTranslation()
  const owners = useOwnerNames()
  const { data: q, mutate } = useTaskQuery(taskId)
  const [rerun, setRerun] = useState<QueryRerunPreview | null>(null)
  const [rerunOpen, setRerunOpen] = useState(false)
  const [busy, setBusy] = useState<'preview' | 'add' | 'auto' | null>(null)
  const [error, setError] = useState<string | null>(null)

  const openRerun = useCallback(async () => {
    setBusy('preview')
    setError(null)
    setRerun(null)
    setRerunOpen(true)
    try {
      setRerun(await taskQueryApi.previewRerun(taskId))
    } catch (err) {
      setError(apiMessage(err, t('remediationQuery.task.rerunFailed')))
    } finally {
      setBusy(null)
    }
  }, [t, taskId])

  const confirmRerun = useCallback(async () => {
    setBusy('add')
    setError(null)
    try {
      const res = await taskQueryApi.rerun(taskId)
      toast.success(t('remediationQuery.task.added', undefined, { count: res.added }))
      setRerunOpen(false)
      void mutate()
      onChanged?.()
    } catch (err) {
      setError(apiMessage(err, t('remediationQuery.task.rerunFailed')))
    } finally {
      setBusy(null)
    }
  }, [mutate, onChanged, t, taskId])

  const setPaused = useCallback(
    async (paused: boolean) => {
      setBusy('auto')
      try {
        await mutate(await taskQueryApi.setAuto(taskId, paused), { revalidate: false })
        toast.success(
          paused ? t('remediationQuery.task.paused') : t('remediationQuery.task.resumed')
        )
      } catch (err) {
        toast.error(apiMessage(err, t('remediationQuery.task.autoFailed')))
      } finally {
        setBusy(null)
      }
    },
    [mutate, t, taskId]
  )

  if (!q) return null
  const isAuto = q.mode === 'auto'
  const lastRun = q.last_run_at ? new Date(q.last_run_at).toLocaleString() : null
  const owner = owners.user(q.owner_user_id ?? undefined) ?? t('remediationQuery.task.ownerGone')

  return (
    <section
      className="space-y-3 rounded-lg border p-4"
      aria-labelledby="task-query-heading"
      data-testid="task-query-panel"
    >
      <div className="flex flex-wrap items-center gap-2">
        <h2 id="task-query-heading" className="text-sm font-semibold">
          {t('remediationQuery.task.heading')}
        </h2>
        <Badge variant="secondary">
          {isAuto ? t('remediationQuery.mode.auto') : t('remediationQuery.mode.snapshot')}
        </Badge>
        {isAuto && q.auto_state && (
          <Badge variant={q.auto_state === 'suspended' ? 'destructive' : 'outline'}>
            {t(`remediationQuery.task.state.${q.auto_state}`)}
          </Badge>
        )}
        <div className="ms-auto flex flex-wrap gap-2">
          {writable && !isAuto && (
            <Button size="sm" variant="outline" onClick={openRerun} disabled={busy !== null}>
              <RefreshCw className="size-4" aria-hidden />
              {t('remediationQuery.task.rerun')}
            </Button>
          )}
          {writable && isAuto && q.auto_state === 'active' && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => void setPaused(true)}
              disabled={busy !== null}
            >
              <PauseCircle className="size-4" aria-hidden />
              {t('remediationQuery.task.pause')}
            </Button>
          )}
          {writable && isAuto && q.auto_state !== 'active' && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => void setPaused(false)}
              disabled={busy !== null}
            >
              <PlayCircle className="size-4" aria-hidden />
              {t('remediationQuery.task.resume')}
            </Button>
          )}
        </div>
      </div>
      <pre className="bg-muted overflow-x-auto rounded p-2 font-mono text-xs whitespace-pre-wrap break-words">
        {q.query}
      </pre>
      {isAuto && q.auto_state === 'suspended' && q.auto_reason && (
        <p role="status" className="text-destructive text-sm">
          {t(`remediationQuery.task.reason.${q.auto_reason}`)}
        </p>
      )}
      <p className="text-muted-foreground text-xs">
        {t('remediationQuery.task.runsAs', undefined, { owner })}
        {isAuto &&
          ` ${t('remediationQuery.task.capInfo', undefined, { cap: q.cap, total: q.total_added })}`}
        {lastRun && ` ${t('remediationQuery.task.lastRun', undefined, { when: lastRun })}`}
      </p>

      <Dialog open={rerunOpen} onOpenChange={setRerunOpen}>
        <DialogContent size="md">
          <DialogHeader>
            <DialogTitle>{t('remediationQuery.task.rerunTitle')}</DialogTitle>
            <DialogDescription>{t('remediationQuery.task.rerunDescription')}</DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-2" aria-live="polite">
            {busy === 'preview' && (
              <Loader2
                className="size-5 animate-spin"
                aria-label={t('remediationQuery.box.checking')}
              />
            )}
            {rerun && (
              <>
                <p className="text-sm">
                  {t(
                    `remediationQuery.task.newMatches.${rerun.new === 1 ? 'one' : 'other'}`,
                    undefined,
                    {
                      count: rerun.new,
                    }
                  )}
                </p>
                {rerun.new > rerun.room && (
                  <p className="text-xs text-warning">
                    {t('remediationQuery.task.roomLimit', undefined, { room: rerun.room })}
                  </p>
                )}
                {rerun.stats && rerun.stats.sample.length > 0 && (
                  <ul className="max-h-48 space-y-1 overflow-auto text-xs">
                    {rerun.stats.sample.map((s) => (
                      <li key={s.finding_id} className="truncate" title={s.title}>
                        {s.title}
                      </li>
                    ))}
                  </ul>
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
            <Button variant="outline" onClick={() => setRerunOpen(false)}>
              {t('remediationQuery.create.cancel')}
            </Button>
            <Button
              onClick={confirmRerun}
              disabled={!rerun || rerun.new === 0 || rerun.room === 0 || busy !== null}
            >
              {busy === 'add' && <Loader2 className="mr-2 size-4 animate-spin" aria-hidden />}
              {t('remediationQuery.task.addConfirm', undefined, {
                count: Math.min(rerun?.new ?? 0, rerun?.room ?? 0),
              })}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  )
}
