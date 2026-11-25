'use client'

import { useEffect, useRef, useState } from 'react'
import Link from '@/components/link'
import { Loader2 } from 'lucide-react'
import { EntryActions, EntryCard, EntryHeader, EntryLinkProblem } from '@/components/entry'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { verifyEmailAction } from '../actions/local-auth-actions'
import { ResendVerification } from './resend-verification'

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

  if (state === 'failed') {
    // One message under a title that names the problem; the way on is a new
    // link (or, on a server without email, who to ask).
    return (
      <EntryLinkProblem
        title={t('auth.verifyEmail.failedTitle', 'This verification link does not work')}
        description={t('auth.verifyEmail.failedBody', 'It may have expired or been used already.')}
      >
        <ResendVerification primary />
      </EntryLinkProblem>
    )
  }

  if (state === 'verified') {
    return (
      <EntryCard>
        <EntryHeader
          title={t('auth.verifyEmail.verifiedTitle', 'Your email is verified')}
          description={
            <span role="status">
              {t('auth.verifyEmail.verified', 'Your email address is verified. You can sign in.')}
            </span>
          }
        />
        <EntryActions>
          <Button asChild variant="signal">
            <Link href="/login">{t('auth.passwordToken.signIn', 'Sign in')}</Link>
          </Button>
        </EntryActions>
      </EntryCard>
    )
  }

  return (
    <EntryCard>
      <EntryHeader title={t('auth.verifyEmail.title', 'Verify your email')} />
      <p className="text-body text-muted-foreground flex items-center gap-2" role="status">
        <Loader2 className="size-4 animate-spin" aria-hidden />
        {t('auth.verifyEmail.verifying', 'Verifying your email address...')}
      </p>
    </EntryCard>
  )
}
