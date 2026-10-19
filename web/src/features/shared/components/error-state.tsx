'use client'

import { AlertCircle, Lock, RefreshCw } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { accessStateOf, errorDetails } from '@/lib/api/access-state'
import { describePermissionDenied } from '@/lib/api/permission-denied'

interface ErrorStateProps {
  /** What failed to load, e.g. "SAML configuration". Phrased into "Failed to load {title}". */
  title: string
  /** The caught error; its message is shown when available. */
  error?: unknown
  /** Retry handler — usually the SWR `mutate` for the failed key. */
  onRetry?: () => void
}

/**
 * Shown when a read fails. Without it, a failed fetch leaves `data` undefined and
 * the page renders its empty state instead — telling the user "nothing here" when
 * the truth is "we could not find out". That misreads badly on security settings
 * (no SSO configured / no verified domains / no API keys) and can lead an admin to
 * re-create something that already exists, or to save over a config they never saw.
 *
 * Rendered as the destructive Alert, the one error surface in the style contract.
 *
 * A refusal is not a failure: a missing permission says so and who can grant
 * it, a switched-off module says that, and neither offers a Retry that cannot
 * help or shows the raw API message.
 */
export function ErrorState({ title, error, onRetry }: ErrorStateProps) {
  const { t } = useTranslation()
  const access = accessStateOf(error)
  if (access === 'no_access' || access === 'module_off') {
    return (
      <Alert>
        <Lock />
        <AlertTitle>
          {access === 'no_access'
            ? t('common.noAccessTo', 'You do not have access to {title}', { title })
            : t('common.moduleOffFor', '{title} is not enabled for this organization', {
                title,
              })}
        </AlertTitle>
        <AlertDescription>
          <p>
            {access === 'no_access'
              ? (describePermissionDenied(errorDetails(error)) ??
                t('common.noAccessHint', 'Ask an organization administrator to grant access.'))
              : t('common.moduleOffHint', 'Ask an organization administrator to enable it.')}
          </p>
        </AlertDescription>
      </Alert>
    )
  }
  return (
    <Alert variant="destructive">
      <AlertCircle />
      <AlertTitle>{t('common.failedToLoad', 'Failed to load {title}', { title })}</AlertTitle>
      <AlertDescription>
        <p>
          {error instanceof Error
            ? error.message
            : t('common.unexpectedError', 'An unexpected error occurred')}
        </p>
        {onRetry && (
          <Button variant="outline" size="sm" className="mt-2" onClick={onRetry}>
            <RefreshCw className="me-2 h-4 w-4" />
            {t('common.retry', 'Retry')}
          </Button>
        )}
      </AlertDescription>
    </Alert>
  )
}
