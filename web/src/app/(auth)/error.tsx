'use client'

import { ReportProblem } from '@/features/shared/components/report-problem'
import { useEffect, useState } from 'react'
import { devLog } from '@/lib/logger'
import { reportRouteError } from '@/lib/error-reporting'
import { useTranslation } from '@/context/i18n-provider'
import Link from '@/components/link'
import { Loader2 } from 'lucide-react'
import { EntryActions, EntryCard, EntryHeader } from '@/components/entry'
import { Button } from '@/components/ui/button'

interface ErrorProps {
  error: Error & { digest?: string; statusCode?: number; code?: string }
  reset: () => void
}

/**
 * Check if error is an authentication error that should trigger redirect to login
 */
function isAuthError(error: Error & { statusCode?: number; code?: string }): boolean {
  // Check status code
  if (error.statusCode === 401 || error.statusCode === 403) {
    return true
  }

  // Check error code
  const code = error.code?.toUpperCase() || ''
  if (code.includes('UNAUTHORIZED') || code.includes('UNAUTHENTICATED') || code.includes('TOKEN')) {
    return true
  }

  // Check error message
  const message = error.message?.toLowerCase() || ''
  if (
    message.includes('unauthorized') ||
    message.includes('unauthenticated') ||
    message.includes('invalid token') ||
    message.includes('expired token') ||
    message.includes('invalid refresh token') ||
    message.includes('session expired') ||
    message.includes('not authenticated') ||
    message.includes('authentication failed')
  ) {
    return true
  }

  return false
}

export default function AuthError({ error, reset }: ErrorProps) {
  const [isRedirecting, setIsRedirecting] = useState(false)
  const { t } = useTranslation()

  useEffect(() => {
    console.error('Auth error:', error)
    // An expired session is not a fault; anything else is counted.
    if (!isAuthError(error)) reportRouteError(error, '/auth')

    // If it's an auth error, redirect to login
    if (isAuthError(error)) {
      devLog.log('[AuthError] Detected auth error, redirecting to login...')
      setIsRedirecting(true)

      // Use hard redirect to clear state and pick up new cookies
      window.location.href = '/login'
    }
  }, [error])

  // Show loading while redirecting for auth errors
  if (isRedirecting) {
    return (
      <EntryCard>
        <EntryHeader title={t('auth.error.sessionExpired', 'Session expired')} />
        <p className="text-body text-muted-foreground flex items-center gap-2">
          <Loader2 aria-hidden className="size-4 animate-spin" />
          {t('auth.error.redirecting', 'Redirecting to sign in...')}
        </p>
      </EntryCard>
    )
  }

  return (
    <EntryCard>
      <EntryHeader
        title={t('auth.error.title', 'Authentication error')}
        description={t('auth.error.body', 'Something went wrong during authentication.')}
      />
      {error.digest && (
        <p className="text-cap text-muted-foreground">
          {t('auth.error.errorId', 'Error ID: {id}', { id: error.digest })}
        </p>
      )}
      <EntryActions>
        <Button variant="signal" onClick={reset}>
          {t('auth.error.tryAgain', 'Try again')}
        </Button>
        <Button variant="outline" asChild>
          <Link href="/login">{t('auth.error.backToSignIn', 'Back to sign in')}</Link>
        </Button>
        <ReportProblem error={error} />
      </EntryActions>
    </EntryCard>
  )
}
