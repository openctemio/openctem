'use client'

/**
 * The chrome New Scan and Edit Scan share: one sticky footer row (Back on the
 * start side, the step's primary action on the end side, the reason a
 * disabled action is disabled under it) and the unsaved-changes prompt behind
 * the header's close button. Cancel lives only in the header X.
 */

import { useState, type ReactNode } from 'react'
import { ChevronLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { DialogFooter } from '@/components/ui/dialog'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'

interface WizardFooterProps {
  /** Go one step back (hidden on the first step). */
  onBack?: () => void
  disabled?: boolean
  /** The step's actions, end side; the primary one last. */
  children: ReactNode
  /** Why the primary action is disabled, or a note about it. */
  note?: ReactNode
  noteId?: string
  noteTone?: 'muted' | 'destructive'
}

export function WizardFooter({
  onBack,
  disabled,
  children,
  note,
  noteId,
  noteTone = 'muted',
}: WizardFooterProps) {
  const { t } = useTranslation()
  return (
    <DialogFooter className="flex-col gap-1.5 sm:flex-col sm:justify-start">
      <div className="flex w-full min-w-0 items-center justify-between gap-2">
        {onBack ? (
          <Button
            type="button"
            variant="outline"
            onClick={onBack}
            disabled={disabled}
            data-testid="wizard-back"
          >
            <ChevronLeft className="me-1 h-4 w-4" aria-hidden />
            {t('scans.common.back')}
          </Button>
        ) : (
          <span aria-hidden />
        )}
        <div className="flex min-w-0 flex-wrap items-center justify-end gap-2">{children}</div>
      </div>
      {note && (
        <p
          id={noteId}
          className={
            noteTone === 'destructive'
              ? 'w-full text-end text-xs text-destructive'
              : 'w-full text-end text-xs text-muted-foreground'
          }
          data-testid="wizard-note"
        >
          {note}
        </p>
      )}
    </DialogFooter>
  )
}

/**
 * Closing with unsaved changes asks first (isDirty is read when closing). `requestClose` is what the header
 * X (the dialog's onOpenChange(false)) calls; `prompt` renders the question.
 */
export function useDiscardPrompt(isDirty: () => boolean, close: () => void) {
  const { t } = useTranslation()
  const [asking, setAsking] = useState(false)
  const requestClose = () => {
    if (isDirty()) setAsking(true)
    else close()
  }
  const prompt = (
    <ConfirmDialog
      open={asking}
      onOpenChange={setAsking}
      title={t('confirm.discardTitle', 'Discard your changes?')}
      desc={t('confirm.discardCloseDesc')}
      cancelBtnText={t('confirm.keepEditing', 'Keep editing')}
      confirmText={t('confirm.discard', 'Discard')}
      destructive
      handleConfirm={() => {
        setAsking(false)
        close()
      }}
    />
  )
  return { requestClose, prompt }
}
