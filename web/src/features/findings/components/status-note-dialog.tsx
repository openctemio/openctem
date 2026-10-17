'use client'

/**
 * Asks for the note a fix claim or a resolve needs. The API applies the same
 * rules on every route: marking a fix applied needs a note, and a resolve
 * without the verification checklist is recorded as attested and needs one.
 */

import { useState } from 'react'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'

export type NotedStatus = 'fix_applied' | 'resolved'

/** The statuses whose change needs a note. */
export function needsStatusNote(status: string): status is NotedStatus {
  return status === 'fix_applied' || status === 'resolved'
}

interface StatusNoteDialogProps {
  status: NotedStatus
  open: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: (note: string) => void
}

export function StatusNoteDialog({ status, open, onOpenChange, onConfirm }: StatusNoteDialogProps) {
  const { t } = useTranslation()
  const [note, setNote] = useState('')
  const trimmed = note.trim()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {status === 'fix_applied'
              ? t('findings.statusNote.title.fix_applied', 'Mark fix applied')
              : t('findings.statusNote.title.resolved', 'Resolve finding')}
          </DialogTitle>
          <DialogDescription>
            {status === 'fix_applied'
              ? t(
                  'findings.statusNote.desc.fix_applied',
                  'Say what was changed. A retest, a covered scan or a security reviewer verifies the fix.'
                )
              : t(
                  'findings.statusNote.desc.resolved',
                  'Say how the fix was verified. Without the verification checklist the close is recorded as attested by you.'
                )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-2">
            <Label htmlFor="status-note">{t('findings.statusNote.label', 'Note (required)')}</Label>
            <Textarea
              id="status-note"
              value={note}
              maxLength={1000}
              rows={3}
              placeholder={t(
                'findings.statusNote.placeholder',
                'e.g. Upgraded the library to 4.2 in release 2026.10'
              )}
              onChange={(e) => setNote(e.target.value)}
            />
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('findings.statusNote.cancel', 'Cancel')}
          </Button>
          <Button disabled={!trimmed} onClick={() => onConfirm(trimmed)}>
            {t('findings.statusNote.confirm', 'Save')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
