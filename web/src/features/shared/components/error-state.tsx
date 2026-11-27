'use client'

import { AlertCircle, Copy, RefreshCw, SearchX } from 'lucide-react'
import { toast } from 'sonner'
import { copyToClipboard } from '@/lib/clipboard'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { accessStateOf, errorDetails } from '@/lib/api/access-state'
import { AccessNotice } from './access-notice'
import { EmptyState } from './empty-state'
import { ReportProblem } from './report-problem'

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
 * help or shows the raw API message. A record that is not there (404, the
 * usual case: a detail page opened from an old link) says so in plain words,
 * without a Retry that cannot bring it back or the server's English message.
 */
type Translate = ReturnType<typeof useTranslation>['t']

/**
 * The sentence shown under the title. A rate limit, a lost connection and a
 * server failure get our own words: the server's text for them is English-only,
 * often a bare code ("internal") and says nothing about what to do. A refusal
 * the server explains in a sentence (a 4xx with a message) keeps that message.
 * The raw details stay one click away in "Copy diagnostics".
 */
function errorMessage(error: unknown, t: Translate): string {
  const status = (error as { statusCode?: unknown } | undefined)?.statusCode
  if (status === 429) {
    return t(
      'common.rateLimited',
      'Too many requests in a short time. Wait a few seconds, then retry.'
    )
  }
  if (error instanceof TypeError && /fetch|network/i.test(error.message)) {
    return t(
      'common.networkError',
      'The server could not be reached. Check your connection, then retry.'
    )
  }
  const message = error instanceof Error ? error.message.trim() : ''
  const sentence = /\s/.test(message)
  if (typeof status === 'number' && status >= 500) return serverFailed(t)
  return message && sentence ? message : serverFailed(t)
}

function serverFailed(t: Translate): string {
  return t(
    'common.loadFailedPlain',
    'The server did not answer. Nothing was changed. Try again; if it keeps failing, report the problem.'
  )
}

export function ErrorState({ title, error, onRetry }: ErrorStateProps) {
  const { t } = useTranslation()
  const access = accessStateOf(error)
  const requestId = (error as { requestId?: unknown } | undefined)?.requestId
  if (access === 'no_access' || access === 'module_off') {
    return <AccessNotice kind={access} title={title} details={errorDetails(error)} />
  }
  if ((error as { statusCode?: unknown } | undefined)?.statusCode === 404) {
    return (
      <EmptyState
        icon={SearchX}
        title={t('common.notFoundTitle', "Couldn't find {title}", { title })}
        description={t(
          'common.notFoundDescription',
          'It may have been deleted, or the link is out of date.'
        )}
      />
    )
  }
  return (
    <Alert variant="destructive">
      <AlertCircle />
      <AlertTitle>{t('common.failedToLoad', "Couldn't load {title}", { title })}</AlertTitle>
      <AlertDescription>
        <p>{errorMessage(error, t)}</p>
        {/* Ink, not the alert's red: these are ways on, not part of the error text. */}
        <div className="mt-2 flex flex-wrap items-center gap-2 text-foreground">
          {onRetry && (
            <Button variant="outline" size="sm" onClick={onRetry}>
              <RefreshCw className="me-2 h-4 w-4" />
              {t('common.retry', 'Retry')}
            </Button>
          )}
          {typeof requestId === 'string' && requestId && (
            // The id is an internal value: the button copies it for a report,
            // it is never printed in the error's text.
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                copyToClipboard(requestId)
                toast.success(t('common.requestIdCopied', 'Request ID copied'))
              }}
            >
              <Copy className="me-2 h-4 w-4" />
              {t('common.copyRequestId', 'Copy request ID')}
            </Button>
          )}
          <ReportProblem error={error} />
        </div>
      </AlertDescription>
    </Alert>
  )
}
