'use client'

/**
 * Findings of another active task (a 409 FINDINGS_IN_OTHER_TASK answer): a
 * finding has one task at a time. Per finding the person skips it (the
 * default) or, when they may change the task that holds it, moves it here
 * with a reason (recorded on both tasks and in the audit log). A task the
 * viewer cannot read is named only as "another task".
 */

import { useEffect, useMemo, useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import type { ConflictResolution, FindingConflict } from '../api/types'
import { useOwnerNames } from '../api/use-owner-names'

const MAX_REASON = 500

export function ConflictDialog({
  conflicts,
  open,
  onOpenChange,
  onResolve,
  busy,
}: {
  conflicts: FindingConflict[]
  open: boolean
  onOpenChange: (open: boolean) => void
  onResolve: (r: ConflictResolution) => void
  busy?: boolean
}) {
  const { t } = useTranslation()
  const owners = useOwnerNames()
  const [moves, setMoves] = useState<Set<string>>(new Set())
  const [reason, setReason] = useState('')
  useEffect(() => {
    if (open) {
      setMoves(new Set())
      setReason('')
    }
  }, [open])

  const resolution = useMemo((): ConflictResolution | null => {
    if (moves.size === 0) return { skip: true }
    if (!reason.trim()) return null
    return { move: [...moves], move_reason: reason.trim() }
  }, [moves, reason])

  const holder = (c: FindingConflict) => {
    if (c.task_title === null) return t('remediationHub.conflicts.otherTask')
    const owner =
      owners.user(c.assignee_user_id ?? undefined) ??
      owners.group(c.assignee_group_id ?? undefined) ??
      (c.assignee_user_id || c.assignee_group_id
        ? t('remediationHub.ownerPicker.unknown')
        : t('remediationHub.owner.unassigned'))
    return t('remediationHub.conflicts.inTask', undefined, { title: c.task_title, owner })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader>
          <DialogTitle>{t('remediationHub.conflicts.title')}</DialogTitle>
          <DialogDescription>
            {t('remediationHub.conflicts.description', undefined, { n: conflicts.length })}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          <ul className="divide-y rounded-md border" data-testid="conflict-list">
            {conflicts.map((c) => {
              const move = moves.has(c.finding_id)
              const name = `conflict-${c.finding_id}`
              return (
                <li key={c.finding_id} className="space-y-2 px-3 py-2">
                  <p className="text-sm font-medium break-words">{c.finding_title}</p>
                  <p className="text-muted-foreground text-xs break-words">{holder(c)}</p>
                  <RadioGroup
                    value={move ? 'move' : 'skip'}
                    onValueChange={(v) =>
                      setMoves((cur) => {
                        const n = new Set(cur)
                        if (v === 'move') n.add(c.finding_id)
                        else n.delete(c.finding_id)
                        return n
                      })
                    }
                    className="flex flex-wrap gap-4"
                    aria-label={t('remediationHub.conflicts.choice', undefined, {
                      title: c.finding_title,
                    })}
                  >
                    <div className="flex items-center gap-2">
                      <RadioGroupItem id={`${name}-skip`} value="skip" />
                      <Label htmlFor={`${name}-skip`} className="font-normal">
                        {t('remediationHub.conflicts.skip')}
                      </Label>
                    </div>
                    <div className="flex items-center gap-2">
                      <RadioGroupItem id={`${name}-move`} value="move" disabled={!c.can_move} />
                      <Label
                        htmlFor={`${name}-move`}
                        className={c.can_move ? 'font-normal' : 'text-muted-foreground font-normal'}
                      >
                        {t('remediationHub.conflicts.move')}
                      </Label>
                    </div>
                  </RadioGroup>
                  {!c.can_move && (
                    <p className="text-muted-foreground text-xs">
                      {t('remediationHub.conflicts.cannotMove')}
                    </p>
                  )}
                </li>
              )
            })}
          </ul>
          {moves.size > 0 && (
            <div className="space-y-1">
              <Label htmlFor="conflict-reason">{t('remediationHub.conflicts.reason')}</Label>
              <Textarea
                id="conflict-reason"
                value={reason}
                maxLength={MAX_REASON}
                onChange={(e) => setReason(e.target.value)}
                aria-required="true"
              />
              <p className="text-muted-foreground text-xs">
                {t('remediationHub.conflicts.reasonHint')}
              </p>
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('remediationHub.actions.cancel')}
          </Button>
          <Button
            onClick={() => resolution && onResolve(resolution)}
            disabled={busy || resolution === null}
          >
            {moves.size > 0
              ? t('remediationHub.conflicts.confirmMove', undefined, { n: moves.size })
              : t('remediationHub.conflicts.confirmSkip')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
