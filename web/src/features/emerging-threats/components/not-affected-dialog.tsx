'use client'

import { useEffect, useState } from 'react'
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
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import { MAX_NOTE_LENGTH, NOT_AFFECTED_REASONS, type NotAffectedReason } from '../types'

interface NotAffectedDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  vulnId: string
  busy?: boolean
  onConfirm: (reason: NotAffectedReason, note: string) => void
}

/** Marks an alert not affected: a reason is required, a note is optional. */
export function NotAffectedDialog({
  open,
  onOpenChange,
  vulnId,
  busy,
  onConfirm,
}: NotAffectedDialogProps) {
  const { t } = useTranslation()
  const [reason, setReason] = useState<NotAffectedReason | ''>('')
  const [note, setNote] = useState('')

  useEffect(() => {
    if (open) {
      setReason('')
      setNote('')
    }
  }, [open])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>{t('emergingThreats.notAffected.title', undefined, { vulnId })}</DialogTitle>
          <DialogDescription>{t('emergingThreats.notAffected.description')}</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          <RadioGroup
            value={reason}
            onValueChange={(v) => setReason(v as NotAffectedReason)}
            aria-label={t('emergingThreats.notAffected.reason')}
          >
            {NOT_AFFECTED_REASONS.map((r) => (
              <div key={r} className="flex items-center gap-2">
                <RadioGroupItem id={`na-${r}`} value={r} />
                <Label htmlFor={`na-${r}`} className="font-normal">
                  {t(`emergingThreats.notAffected.reasons.${r}`)}
                </Label>
              </div>
            ))}
          </RadioGroup>
          <div className="space-y-1">
            <Label htmlFor="na-note">{t('emergingThreats.notAffected.note')}</Label>
            <Textarea
              id="na-note"
              value={note}
              maxLength={MAX_NOTE_LENGTH}
              onChange={(e) => setNote(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              {t('emergingThreats.notAffected.noteCount', undefined, {
                n: note.length,
                max: MAX_NOTE_LENGTH,
              })}
            </p>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('emergingThreats.actions.cancel')}
          </Button>
          <Button disabled={busy || !reason} onClick={() => reason && onConfirm(reason, note)}>
            {t('emergingThreats.notAffected.confirm')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
