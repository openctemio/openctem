'use client'

import type * as React from 'react'
import { AlertTriangle } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { SECTION_X, useModalLayout } from '@/components/ui/modal-layout'
import { useTranslation } from '@/context/i18n-provider'

/**
 * Why a dialog's or sheet's submit failed. Put it between the body and the
 * footer, directly above the buttons: the body scrolls, the person is at the
 * bottom next to the submit button, and an alert at the top of the body is out
 * of view there ("nothing happened"). It is an alert region, so a screen
 * reader announces it when it appears.
 *
 *   <DialogBody>…fields (their own errors beside them)…</DialogBody>
 *   <DialogSubmitError message={error} requestId={requestId} />
 *   <DialogFooter>…</DialogFooter>
 *
 * Field-level errors stay next to their fields. `requestId` is the server's
 * request id (ApiClientError.requestId): shown as a small "Reference" line to
 * quote to support.
 */
export function DialogSubmitError({
  message,
  requestId,
  className,
  children,
  testId,
}: {
  message?: string | null
  requestId?: string | null
  className?: string
  /** More under the message: a hint or a link to fix it. */
  children?: React.ReactNode
  testId?: string
}) {
  const { t } = useTranslation()
  const layout = useModalLayout()
  if (!message) return null
  return (
    <div
      data-slot="dialog-submit-error"
      className={cn(layout?.sections ? ['shrink-0 pt-3', SECTION_X] : 'mt-2', className)}
    >
      <Alert variant="destructive" data-testid={testId}>
        <AlertTriangle aria-hidden />
        <AlertDescription>
          <p>{message}</p>
          {children}
          {requestId ? (
            <p className="text-xs opacity-80">
              {t('components.dialogSubmitError.reference', 'Reference')}:{' '}
              <span className="font-mono break-all">{requestId}</span>
            </p>
          ) : null}
        </AlertDescription>
      </Alert>
    </div>
  )
}
