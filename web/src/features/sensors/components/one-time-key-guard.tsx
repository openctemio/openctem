'use client'

import type * as React from 'react'
import { useState } from 'react'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'

/**
 * Keeps a dialog that shows a one-time key from being dismissed by accident.
 * While `active` (the key is on screen) an outside click does nothing, and
 * Esc or the close button ask "Did you copy the key?" first. Spread
 * `contentProps` on the DialogContent, pass `requestClose` as the dialog's
 * onOpenChange handler and render `confirm` next to the dialog.
 */
export function useOneTimeKeyGuard(active: boolean, onClose: () => void) {
  const { t } = useTranslation()
  const [asking, setAsking] = useState(false)

  const requestClose = () => {
    if (active) setAsking(true)
    else onClose()
  }

  const contentProps = active
    ? {
        onPointerDownOutside: (e: Event) => e.preventDefault(),
        onInteractOutside: (e: Event) => e.preventDefault(),
        onEscapeKeyDown: (e: KeyboardEvent) => {
          e.preventDefault()
          setAsking(true)
        },
      }
    : {}

  const confirm: React.ReactNode = (
    <ConfirmDialog
      open={asking}
      onOpenChange={setAsking}
      title={t('sensors.keyGuard.title')}
      desc={t('sensors.keyGuard.desc')}
      confirmText={t('sensors.keyGuard.confirm')}
      cancelBtnText={t('sensors.keyGuard.cancel')}
      destructive
      handleConfirm={() => {
        setAsking(false)
        onClose()
      }}
    />
  )

  return { requestClose, contentProps, confirm }
}
