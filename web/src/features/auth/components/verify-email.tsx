'use client'

import { useEffect, useRef, useState } from 'react'
import Link from '@/components/link'
import { Loader2 } from 'lucide-react'
import { EntryActions, EntryBanner, EntryCard, EntryHeader } from '@/components/entry'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { verifyEmailAction } from '../actions/local-auth-actions'
import { ResendVerification } from './resend-verification'
import { useEmailUnavailable } from '../api/use-auth-providers'

type State = 'verifying' | 'verified' | 'failed'

/**
 * Verifies an email address from the emailed link (/verify-email#token=...).
 * The token is in the URL fragment (never sent to a server or logged); it is
 * read once, removed from the address bar and posted in the request body.
 */
export function VerifyEmail() {
  const { t } = useTranslation()
  const [state, setState] = useState<State>('verifying')
  const emailUnavailable = useEmailUnavailable()
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
    <EntryCard>
      <EntryHeader title={t('auth.verifyEmail.title', 'Verify your email')} />
      {state === 'verifying' ? (
        <p className="text-body text-muted-foreground flex items-center gap-2" role="status">
          <Loader2 className="size-4 animate-spin" aria-hidden />
          {t('auth.verifyEmail.verifying', 'Verifying your email address...')}
        </p>
      ) : (
        <EntryBanner tone={state === 'verified' ? 'ok' : 'danger'} role="status">
          {state === 'verified'
            ? t('auth.verifyEmail.verified', 'Your email address is verified. You can sign in.')
            : t('auth.verifyEmail.failed', 'This link is invalid or has expired.')}
        </EntryBanner>
      )}
      {state === 'failed' && <ResendVerification primary />}
      <EntryActions>
        {/* Sign in is the main action unless a new link can be sent from here. */}
        <Button
          asChild
          variant={
            state === 'verified' || (state === 'failed' && emailUnavailable) ? 'signal' : 'outline'
          }
        >
          <Link href="/login">{t('auth.notSetUp.backToSignIn', 'Back to sign in')}</Link>
        </Button>
      </EntryActions>
    </EntryCard>
  )
}
