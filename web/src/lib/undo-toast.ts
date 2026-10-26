/**
 * Undo toast for reversible changes to one item (research/213, tier T0).
 *
 * A reversible, low-stakes change (status, assignee, archive, watcher, a
 * dismissed suggestion) is committed at once and gets no confirmation dialog:
 * a dialog on every click trains people to click through dialogs, including
 * the ones that matter. Instead the toast offers Undo, which sends the
 * inverse command to the server. Nothing is held back on the client, so
 * closing the page while the toast is open loses nothing.
 *
 * Never use this for an action that cannot be reversed by a server command
 * (hard delete, key revoke, a scan that already sent traffic): those need
 * ConfirmDialog.
 */
import { toast } from 'sonner'

import { getErrorMessage } from '@/lib/api/error-handler'

/** Only the key and its English fallback are used here. */
type TranslateFn = (key: string, fallback?: string) => string

/** Long enough to notice a mis-tap and reach Undo (research/213: at least 8 s). */
export const UNDO_TOAST_MS = 10_000

export interface UndoToastOptions {
  /** What happened, e.g. "Finding marked as resolved". */
  message: string
  /** Sends the inverse command. A rejected promise shows `failedMessage`. */
  undo: () => unknown
  t: TranslateFn
  /**
   * Shown when the undo succeeds. Defaults to "Change undone". False when the
   * inverse command reports its own result (it toasts and never rejects).
   */
  undoneMessage?: string | false
  /** Fallback when the undo fails without a server message. */
  failedMessage?: string
  /** Runs after a successful undo, e.g. to refresh a list. */
  onUndone?: () => void
}

/** Shows a success toast with an Undo action that runs the inverse command. */
export function undoToast(opts: UndoToastOptions): string | number {
  const { message, undo, t, undoneMessage, failedMessage, onUndone } = opts
  let used = false
  return toast.success(message, {
    duration: UNDO_TOAST_MS,
    action: {
      label: t('confirm.undo', 'Undo'),
      onClick: () => {
        // One undo per toast: a double click must not send the inverse twice.
        if (used) return
        used = true
        Promise.resolve()
          .then(() => undo())
          .then(
            () => {
              if (undoneMessage !== false)
                toast.success(undoneMessage ?? t('confirm.undone', 'Change undone'))
              onUndone?.()
            },
            (err: unknown) => {
              toast.error(
                getErrorMessage(err, failedMessage ?? t('confirm.undoFailed', 'Could not undo'))
              )
            }
          )
      },
    },
  })
}
