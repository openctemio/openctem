'use client'

import { useEffect, useId, useLayoutEffect, useRef, type ReactNode } from 'react'
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

/** A control, with the queue item it belongs to and its slot, to find it again. */
function describeOpener(el: HTMLElement) {
  return {
    el,
    item: el.closest<HTMLElement>('[data-queue-item]')?.dataset.queueItem,
    slot: el.dataset.slot,
  }
}

/**
 * The reason dialog of a queue decision (Reject, and any decision the queue
 * asks a reason for): what is being decided, one required reason field with
 * its length, and the decision button. A failed save keeps the dialog open
 * with the reason as typed and says why, so nobody writes it twice.
 *
 * The page owns the state and the request; this is the one frame.
 *
 * Closing it puts the focus back on the control that opened it (the row's
 * Reject), so a keyboard user carries on from the same row.
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
  // The control that had the focus when the dialog opened, and how to find it
  // again: a list may draw the row's cell anew when the dialog opens (even in
  // the same render), so the node itself can be gone. While the dialog is
  // closed every focus is noted; opening keeps the last one.
  const opener = useRef<{ el: HTMLElement; item?: string; slot?: string } | null>(null)
  useEffect(() => {
    if (open) return
    const note = (e: FocusEvent) => {
      if (e.target instanceof HTMLElement) opener.current = describeOpener(e.target)
    }
    document.addEventListener('focusin', note)
    return () => document.removeEventListener('focusin', note)
  }, [open])
  useLayoutEffect(() => {
    const el = document.activeElement
    if (open && el instanceof HTMLElement && el !== document.body) {
      opener.current = describeOpener(el)
    }
  }, [open])
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        size="sm"
        onCloseAutoFocus={(e) => {
          // Back to the opener, or to the same control of the same item when
          // the list drew it anew; a decided item may be gone, and then the
          // dialog's default applies.
          const from = opener.current
          opener.current = null
          const again =
            from?.item && from.slot
              ? document.querySelector<HTMLElement>(
                  `[data-queue-item="${CSS.escape(from.item)}"] [data-slot="${CSS.escape(from.slot)}"]`
                )
              : null
          const target = from?.el.isConnected ? from.el : again
          if (target) {
            e.preventDefault()
            target.focus()
          }
        }}
      >
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
