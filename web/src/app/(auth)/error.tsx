'use client'

import { useEffect, useState } from 'react'
import { devLog } from '@/lib/logger'
import { reportRouteError } from '@/lib/error-reporting'
import { useTranslation } from '@/context/i18n-provider'
import Link from '@/components/link'
import { AlertCircle, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'

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
      <div className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
            <CardTitle>
              <h1>{t('auth.error.sessionExpired', 'Session expired')}</h1>
            </CardTitle>
            <CardDescription>
              {t('auth.error.redirecting', 'Redirecting to sign in...')}
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-destructive/10">
            <AlertCircle className="h-6 w-6 text-destructive" />
          </div>
          <CardTitle>
            <h1>{t('auth.error.title', 'Authentication error')}</h1>
          </CardTitle>
          <CardDescription>
            {t('auth.error.body', 'Something went wrong during authentication.')}
          </CardDescription>
        </CardHeader>
        <CardContent className="text-center">
          {error.digest && (
            <p className="text-muted-foreground text-sm">
              {t('auth.error.errorId', 'Error ID: {id}', { id: error.digest })}
            </p>
          )}
        </CardContent>
        <CardFooter className="flex justify-center gap-2">
          <Button onClick={reset}>{t('auth.error.tryAgain', 'Try again')}</Button>
          <Button variant="outline" asChild>
            <Link href="/login">{t('auth.error.backToSignIn', 'Back to sign in')}</Link>
          </Button>
        </CardFooter>
      </Card>
    </div>
  )
}
