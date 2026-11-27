'use client'

/**
 * Leaving a form with unsaved changes asks first.
 *
 * - A form in a dialog: `useDiscardPrompt` sits behind the header X, Escape
 *   and a click outside. With `keep`, the question also offers "Keep as
 *   draft", which closes and keeps the draft for the next open.
 * - A form on a page: `LeaveGuard` asks on in-app links, and the browser
 *   asks on reload or close. (A settings form gets this from its save bar.)
 */

import { useState, type ReactNode } from 'react'
import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { useUnsavedChangesGuard } from '@/hooks/use-unsaved-changes-guard'

export interface DiscardPromptOptions {
  /** Close and keep the draft (adds "Keep as draft" to the question). */
  keep?: () => void
  /** The question with a draft (defaults to the general wording). */
  keepTitle?: string
  keepDescription?: string
  keepLabel?: string
}

/**
 * Closing with unsaved changes asks first (isDirty is read when closing).
 * `requestClose` is what the dialog's onOpenChange(false) calls; `prompt`
 * renders the question.
 */
export function useDiscardPrompt(
  isDirty: () => boolean,
  close: () => void,
  options: DiscardPromptOptions = {}
): { requestClose: () => void; prompt: ReactNode } {
  const { t } = useTranslation()
  const [asking, setAsking] = useState(false)
  const { keep, keepTitle, keepDescription, keepLabel } = options
  const requestClose = () => {
    if (isDirty()) setAsking(true)
    else close()
  }
  const prompt = keep ? (
    <AlertDialog open={asking} onOpenChange={setAsking}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{keepTitle ?? t('common.leaveGuard.keepTitle')}</AlertDialogTitle>
          <AlertDialogDescription>
            {keepDescription ?? t('common.leaveGuard.keepDesc')}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>{t('confirm.keepEditing', 'Keep editing')}</AlertDialogCancel>
          <Button
            type="button"
            variant="destructive"
            onClick={() => {
              setAsking(false)
              close()
            }}
          >
            {t('confirm.discard', 'Discard')}
          </Button>
          <AlertDialogAction
            onClick={() => {
              setAsking(false)
              keep()
            }}
          >
            {keepLabel ?? t('common.leaveGuard.keepDraft')}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  ) : (
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

/**
 * The leave guard of a form on a page: while `dirty`, the browser asks on
 * reload or close, and an in-app link is held until the person chooses to
 * stay or to leave and discard.
 */
export function LeaveGuard({ dirty, onDiscard }: { dirty: boolean; onDiscard?: () => void }) {
  const { t } = useTranslation()
  const router = useRouter()
  const [leaveTo, setLeaveTo] = useState<string | null>(null)
  useUnsavedChangesGuard(dirty, setLeaveTo)
  return (
    <ConfirmDialog
      open={leaveTo !== null}
      onOpenChange={(open) => !open && setLeaveTo(null)}
      destructive
      title={t('common.leaveGuard.leaveTitle')}
      desc={t('common.leaveGuard.leaveDesc')}
      cancelBtnText={t('common.leaveGuard.stay')}
      confirmText={t('common.leaveGuard.leave')}
      handleConfirm={() => {
        const to = leaveTo
        setLeaveTo(null)
        onDiscard?.()
        if (to) router.push(to)
      }}
    />
  )
}
