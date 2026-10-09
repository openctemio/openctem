'use client'

import { useEffect, useRef, useState } from 'react'
import Link from '@/components/link'
import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { verifyEmailAction } from '../actions/local-auth-actions'

type State = 'verifying' | 'verified' | 'failed'

/**
 * Verifies an email address from the emailed link (/verify-email#token=...).
 * The token is in the URL fragment (never sent to a server or logged); it is
 * read once, removed from the address bar and posted in the request body.
 */
export function VerifyEmail() {
  const { t } = useTranslation()
  const [state, setState] = useState<State>('verifying')
  const ran = useRef(false)

  useEffect(() => {
    if (ran.current) return
    ran.current = true
    const token = new URLSearchParams(window.location.hash.slice(1)).get('token') ?? ''
    window.history.replaceState(null, '', window.location.pathname)
    if (!token) {
      setState('failed')
      return
    }
    void verifyEmailAction(token).then((res) => setState(res.success ? 'verified' : 'failed'))
  }, [])

  return (
    <div className="mx-auto flex w-full max-w-md flex-col items-center gap-4 text-center">
      {state === 'verifying' ? (
        <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
          <Loader2 className="size-4 animate-spin" aria-hidden />
          {t('auth.verifyEmail.verifying', 'Verifying your email address...')}
        </p>
      ) : (
        <p className="text-sm" role="status">
          {state === 'verified'
            ? t('auth.verifyEmail.verified', 'Your email address is verified. You can sign in.')
            : t('auth.verifyEmail.failed', 'This link is invalid or has expired.')}
        </p>
      )}
      <Button asChild variant="outline">
        <Link href="/login">{t('auth.notSetUp.backToSignIn', 'Back to sign in')}</Link>
      </Button>
    </div>
  )
}
