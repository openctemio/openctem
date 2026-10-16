'use client'

/** Mark a task fixed, split findings off it, cancel it. */

import { useEffect, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
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
import type { MarkFixedResult, RemediationTask } from '../api/types'
import { useOwnerNames } from '../api/use-owner-names'

export function MarkFixedDialog({
  task,
  open,
  onOpenChange,
  onConfirm,
  busy,
  result,
}: {
  task: RemediationTask
  open: boolean
  onOpenChange: (o: boolean) => void
  onConfirm: (note: string) => void
  busy?: boolean
  result?: MarkFixedResult | null
}) {
  const { t } = useTranslation()
  const [note, setNote] = useState('')
  useEffect(() => {
    if (open) setNote('')
  }, [open])
  const openCount = task.counts.open + task.counts.in_progress
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('remediationHub.markFixed.title')}</DialogTitle>
          <DialogDescription>
            {t('remediationHub.markFixed.description', undefined, { n: openCount })}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-3">
          {result ? (
            <div className="space-y-2 text-sm" data-testid="mark-fixed-result">
              <p>
                {t('remediationHub.markFixed.result', undefined, {
                  updated: result.updated,
                  skipped: result.skipped,
                  failed: result.failed,
                  queued: result.validations_queued,
                })}
              </p>
              {result.rows.filter((r) => r.outcome === 'failed').length > 0 && (
                <ul className="text-muted-foreground list-disc space-y-1 ps-5 text-xs">
                  {result.rows
                    .filter((r) => r.outcome === 'failed')
                    .map((r) => (
                      <li key={r.finding_id}>{r.reason}</li>
                    ))}
                </ul>
              )}
            </div>
          ) : (
            <>
              <Label htmlFor="mark-fixed-note">{t('remediationHub.markFixed.note')}</Label>
              <Textarea
                id="mark-fixed-note"
                value={note}
                maxLength={2000}
                placeholder={t('remediationHub.markFixed.notePlaceholder')}
                onChange={(e) => setNote(e.target.value)}
              />
              <p className="text-muted-foreground text-xs">{t('remediationHub.markFixed.hint')}</p>
            </>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {result ? t('remediationHub.actions.close') : t('remediationHub.actions.cancel')}
          </Button>
          {!result && (
            <Button onClick={() => onConfirm(note.trim())} disabled={busy || !note.trim()}>
              {t('remediationHub.markFixed.confirm')}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

const KEEP = '__keep__'

export function SplitDialog({
  task,
  count,
  open,
  onOpenChange,
  onConfirm,
  busy,
}: {
  task: RemediationTask
  count: number
  open: boolean
  onOpenChange: (o: boolean) => void
  onConfirm: (body: {
    title: string
    assignee_user_id?: string
    assignee_group_id?: string
  }) => void
  busy?: boolean
}) {
  const { t } = useTranslation()
  const owners = useOwnerNames()
  const [title, setTitle] = useState('')
  const [user, setUser] = useState(KEEP)
  const [group, setGroup] = useState(KEEP)
  useEffect(() => {
    if (open) {
      setTitle(task.title)
      setUser(KEEP)
      setGroup(KEEP)
    }
  }, [open, task.title])
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('remediationHub.split.title', undefined, { n: count })}</DialogTitle>
          <DialogDescription>{t('remediationHub.split.description')}</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          <div className="space-y-1">
            <Label htmlFor="split-title">{t('remediationHub.accept.taskTitle')}</Label>
            <Input
              id="split-title"
              value={title}
              maxLength={300}
              onChange={(e) => setTitle(e.target.value)}
            />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <Select value={user} onValueChange={setUser}>
              <SelectTrigger aria-label={t('remediationHub.accept.user')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={KEEP}>{t('remediationHub.split.keepOwner')}</SelectItem>
                {owners.users.map((u) => (
                  <SelectItem key={u.id} value={u.id}>
                    {u.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={group} onValueChange={setGroup}>
              <SelectTrigger aria-label={t('remediationHub.accept.group')}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={KEEP}>{t('remediationHub.split.keepGroup')}</SelectItem>
                {owners.groups.map((g) => (
                  <SelectItem key={g.id} value={g.id}>
                    {g.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('remediationHub.actions.cancel')}
          </Button>
          <Button
            disabled={busy || !title.trim()}
            onClick={() =>
              onConfirm({
                title: title.trim(),
                ...(user !== KEEP ? { assignee_user_id: user } : {}),
                ...(group !== KEEP ? { assignee_group_id: group } : {}),
              })
            }
          >
            {t('remediationHub.split.confirm')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export function CancelTaskDialog({
  open,
  onOpenChange,
  onConfirm,
  busy,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  onConfirm: (note: string) => void
  busy?: boolean
}) {
  const { t } = useTranslation()
  const [note, setNote] = useState('')
  useEffect(() => {
    if (open) setNote('')
  }, [open])
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{t('remediationHub.cancelTask.title')}</DialogTitle>
          <DialogDescription>{t('remediationHub.cancelTask.description')}</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-2">
          <Label htmlFor="cancel-note">{t('remediationHub.cancelTask.reason')}</Label>
          <Textarea
            id="cancel-note"
            value={note}
            maxLength={500}
            onChange={(e) => setNote(e.target.value)}
          />
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('remediationHub.actions.back')}
          </Button>
          <Button
            variant="destructive"
            disabled={busy || !note.trim()}
            onClick={() => onConfirm(note.trim())}
          >
            {t('remediationHub.cancelTask.confirm')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
