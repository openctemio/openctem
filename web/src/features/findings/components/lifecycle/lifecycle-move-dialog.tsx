'use client'

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
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'
import type { TransitionDecision } from '../../api/use-finding-transitions'

const FIELD_INPUT_TYPE: Record<string, string> = {
  ticket_link: 'url',
  fix_reference: 'text',
  due_date: 'date',
}

const FIELD_PLACEHOLDER: Record<string, string> = {
  ticket_link: 'https://tickets.example.com/SEC-123',
  fix_reference: 'https://git.example.com/app/pull/42',
}

export interface LifecycleMoveInput {
  note?: string
  fields?: Record<string, string>
}

interface LifecycleMoveDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Where the move lands, as the menu named it. */
  targetLabel: string
  move: TransitionDecision
  /** The platform needs a note for this status (fix applied, resolve). */
  noteRequired: boolean
  onConfirm: (input: LifecycleMoveInput) => void
}

/**
 * Collects what the organization's lifecycle asks of a move: a note of at
 * least the given length and the required fields. The API checks every value
 * again (a link is http(s), a due date is a date) and refuses a move that
 * lacks one.
 */
export function LifecycleMoveDialog({
  open,
  onOpenChange,
  targetLabel,
  move,
  noteRequired,
  onConfirm,
}: LifecycleMoveDialogProps) {
  const { t } = useTranslation()
  const [note, setNote] = useState('')
  const [values, setValues] = useState<Record<string, string>>({})
  const fields = move.fields ?? []
  const minLen = Math.max(move.note_min_len ?? 0, noteRequired ? 1 : 0)
  const showNote = minLen > 0 || (move.requires ?? []).includes('note')
  const trimmed = note.trim()
  const noteOk = trimmed.length >= minLen
  const fieldsOk = fields.every((f) => (values[f] ?? '').trim() !== '')

  const confirm = () => {
    if (!noteOk || !fieldsOk) return
    const out: Record<string, string> = {}
    for (const f of fields) out[f] = values[f].trim()
    onConfirm({ note: trimmed || undefined, fields: fields.length ? out : undefined })
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="md">
        <DialogHeader>
          <DialogTitle>
            {t('findingLifecycle.move.title', 'Move to {target}', { target: targetLabel })}
          </DialogTitle>
          <DialogDescription>
            {t(
              'findingLifecycle.move.hint',
              "Your organization's lifecycle asks for the details below. They are kept on the finding's timeline."
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          {fields.map((f) => (
            <div key={f} className="space-y-1.5">
              <Label htmlFor={`move-field-${f}`}>{t(`findingLifecycle.field.${f}`, f)}</Label>
              <Input
                id={`move-field-${f}`}
                type={FIELD_INPUT_TYPE[f] ?? 'text'}
                maxLength={f === 'ticket_link' || f === 'fix_reference' ? 2048 : 200}
                placeholder={FIELD_PLACEHOLDER[f]}
                value={values[f] ?? ''}
                onChange={(e) => setValues((cur) => ({ ...cur, [f]: e.target.value }))}
              />
            </div>
          ))}
          {showNote && (
            <div className="space-y-1.5">
              <Label htmlFor="move-note">
                {minLen > 1
                  ? t('findingLifecycle.move.noteMin', 'Note (at least {n} characters)', {
                      n: minLen,
                    })
                  : t('findingLifecycle.move.note', 'Note (required)')}
              </Label>
              <Textarea
                id="move-note"
                rows={3}
                maxLength={1000}
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
              {minLen > 1 && (
                <p className="text-xs text-muted-foreground tabular-nums">
                  {t('findingLifecycle.move.count', '{count} of {n}', {
                    count: trimmed.length,
                    n: minLen,
                  })}
                </p>
              )}
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button disabled={!noteOk || !fieldsOk} onClick={confirm}>
            {t('findingLifecycle.move.confirm', 'Move')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
