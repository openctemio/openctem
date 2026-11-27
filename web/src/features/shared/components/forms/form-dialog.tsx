'use client'

/**
 * The frame of a create or edit dialog: a title, a body that is the only
 * part that scrolls, and a footer that stays in view with Cancel and ONE
 * primary action. It is a form, so Enter in a field submits. On a phone it
 * is a bottom sheet (the dialog kit), the primary action on top.
 *
 *   <FormDialog
 *     open={open}
 *     onOpenChange={setOpen}
 *     title={t('assets.group.createTitle')}
 *     submitLabel={t('common.create')}
 *     onSubmit={save}
 *     submitting={saving}
 *     dirty={isDirty}
 *   >
 *     <FormStack>...fields...</FormStack>
 *   </FormDialog>
 *
 * With `dirty`, closing (X, Escape, a click outside, Cancel) asks before the
 * changes are dropped. While `submitting`, the dialog cannot be closed.
 */

import { useId, type FormEvent, type ReactNode } from 'react'
import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogTitle,
  type DialogSize,
} from '@/components/ui/dialog'
import { DialogSubmitError } from '@/components/ui/dialog-submit-error'
import { useTranslation } from '@/context/i18n-provider'
import { useDiscardPrompt } from './leave-guard'

export interface FormDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: ReactNode
  description?: ReactNode
  /** sm, md (default), lg for long forms, xl for editors. */
  size?: DialogSize
  /** The fields (a FormStack). */
  children: ReactNode
  onSubmit: () => void
  /**
   * The primary action's label (a verb: Create, Save, Add). null leaves the
   * primary out: a view-only form for someone who may not change it, closed
   * by Cancel (labelled Close by the caller), X or Escape.
   */
  submitLabel: ReactNode | null
  submitting?: boolean
  /** False while the form cannot be submitted (the button is disabled). */
  canSubmit?: boolean
  /** Why the primary action is disabled; read with the button. */
  reason?: ReactNode
  /** The primary action removes or revokes something. */
  destructive?: boolean
  /**
   * The Cancel button's label. null leaves Cancel out: a result view whose
   * one action (Done) closes the dialog; X and Escape still close it.
   */
  cancelLabel?: ReactNode | null
  /** A failure of the last submit, shown above the actions and announced. */
  error?: string | null
  /** The server's request id of that failure, to quote to support. */
  requestId?: string | null
  /** At the start of the footer row (a secondary action such as "Test"). */
  footerStart?: ReactNode
  /** Unsaved changes exist: closing asks first. */
  dirty?: boolean
  'data-testid'?: string
}

export function FormDialog({
  open,
  onOpenChange,
  title,
  description,
  size = 'md',
  children,
  onSubmit,
  submitLabel,
  submitting = false,
  canSubmit = true,
  reason,
  destructive = false,
  cancelLabel,
  error,
  requestId,
  footerStart,
  dirty = false,
  'data-testid': testId,
}: FormDialogProps) {
  const { t } = useTranslation()
  const reasonId = useId()
  const { requestClose, prompt } = useDiscardPrompt(
    () => dirty,
    () => onOpenChange(false)
  )
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    e.stopPropagation()
    if (submitting || !canSubmit || submitLabel === null) return
    onSubmit()
  }
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) onOpenChange(true)
        else if (!submitting) requestClose()
      }}
    >
      <DialogContent size={size} data-testid={testId}>
        <DialogHeader>
          <DialogTitle className="text-dialog">{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        <DialogForm onSubmit={submit} noValidate>
          <DialogBody>{children}</DialogBody>
          <DialogSubmitError message={error} requestId={requestId} testId="form-dialog-error" />
          <DialogFooter>
            {footerStart && (
              <div className="flex min-w-0 flex-wrap items-center gap-2 sm:me-auto">
                {footerStart}
              </div>
            )}
            {cancelLabel !== null && (
              <Button type="button" variant="ghost" onClick={requestClose} disabled={submitting}>
                {cancelLabel ?? t('common.cancel')}
              </Button>
            )}
            {/* The reason sits beside the off main button: before it on a wide footer, right under
                it on a phone (the footer stacks in reverse there), never under Cancel. */}
            {reason && !canSubmit && (
              <p
                id={reasonId}
                data-slot="form-dialog-reason"
                className="min-w-0 self-center text-cap text-muted-foreground max-sm:text-center sm:max-w-[18rem] sm:text-end"
              >
                {reason}
              </p>
            )}
            {submitLabel !== null && (
              <Button
                type="submit"
                variant={destructive ? 'destructive' : 'default'}
                disabled={submitting || !canSubmit}
                aria-describedby={reason && !canSubmit ? reasonId : undefined}
                data-testid="form-dialog-submit"
              >
                {submitting && <Loader2 className="animate-spin" aria-hidden />}
                {submitLabel}
              </Button>
            )}
          </DialogFooter>
        </DialogForm>
      </DialogContent>
      {prompt}
    </Dialog>
  )
}
