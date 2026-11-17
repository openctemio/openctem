'use client'

import { useId, type ReactNode } from 'react'
import { Loader2 } from 'lucide-react'
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
import { Textarea } from '@/components/ui/textarea'
import { useTranslation } from '@/context/i18n-provider'

/**
 * The reason dialog of a queue decision (Reject, and any decision the queue
 * asks a reason for): what is being decided, one required reason field with
 * its length, and the decision button. A failed save keeps the dialog open
 * with the reason as typed and says why, so nobody writes it twice.
 *
 * The page owns the state and the request; this is the one frame.
 */
export function QueueReasonDialog({
  open,
  onOpenChange,
  title,
  description,
  summary,
  reason,
  onReasonChange,
  reasonLabel,
  maxLength = 2000,
  error,
  busy = false,
  confirmLabel,
  busyLabel,
  cancelLabel,
  destructive = true,
  onConfirm,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description: string
  /** The item the decision is about (never decide blind). */
  summary?: ReactNode
  reason: string
  onReasonChange: (next: string) => void
  /** The field's accessible name and placeholder. */
  reasonLabel: string
  maxLength?: number
  /** Why the save failed; the dialog stays open. */
  error?: string | null
  busy?: boolean
  confirmLabel: string
  busyLabel?: string
  cancelLabel?: string
  destructive?: boolean
  onConfirm: () => void
}) {
  const { t } = useTranslation()
  const errorId = useId()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogBody className="grid gap-4">
          {summary}
          <div className="grid gap-2">
            <Textarea
              placeholder={reasonLabel}
              value={reason}
              onChange={(e) => onReasonChange(e.target.value)}
              rows={3}
              maxLength={maxLength}
              aria-label={reasonLabel}
              aria-required="true"
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? errorId : undefined}
            />
            {error && (
              <p id={errorId} role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            <p className="text-end text-xs text-muted-foreground tabular-nums">
              {reason.length}/{maxLength}
            </p>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            {cancelLabel ?? t('queue.reason.cancel', 'Cancel')}
          </Button>
          <Button
            variant={destructive ? 'destructive' : 'default'}
            onClick={onConfirm}
            disabled={busy || !reason.trim()}
          >
            {busy ? (
              <>
                <Loader2 className="me-2 h-4 w-4 animate-spin" aria-hidden />
                {busyLabel ?? confirmLabel}
              </>
            ) : (
              confirmLabel
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
