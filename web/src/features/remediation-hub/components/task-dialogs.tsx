'use client'

/** Mark a task fixed, split findings off it, cancel it. */

import { useEffect, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
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
import { OwnerCombobox, type OwnerValue } from './owner-combobox'

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
  const [owner, setOwner] = useState<OwnerValue | null>(null)
  useEffect(() => {
    if (open) {
      setTitle(task.title)
      setOwner(null)
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
          <div className="space-y-1">
            <Label htmlFor="split-owner">{t('remediationHub.split.owner')}</Label>
            <OwnerCombobox
              id="split-owner"
              label={t('remediationHub.split.owner')}
              value={owner ?? { userId: task.assignee_user_id, groupId: task.assignee_group_id }}
              suggested={{ userId: task.assignee_user_id, groupId: task.assignee_group_id }}
              suggestedLabel={t('remediationHub.split.current')}
              onChange={setOwner}
              users={owners.users}
              groups={owners.groups}
              usersState={owners.usersState}
              groupsState={owners.groupsState}
            />
            <p className="text-muted-foreground text-xs">{t('remediationHub.split.keepOwner')}</p>
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
                ...(owner?.userId ? { assignee_user_id: owner.userId } : {}),
                ...(owner?.groupId ? { assignee_group_id: owner.groupId } : {}),
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
