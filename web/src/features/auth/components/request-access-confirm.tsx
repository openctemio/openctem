'use client'

import { useEffect, useRef, useState } from 'react'
import Link from 'next/link'
import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { confirmAccessRequestAction } from '../actions/local-auth-actions'

type State = 'confirming' | 'confirmed' | 'failed'

/**
 * Confirms an access request from the emailed link. The token is in the URL
 * fragment (never sent to a server or logged); it is read once, removed from
 * the address bar and posted in the request body.
 */
export function RequestAccessConfirm() {
  const { t } = useTranslation()
  const [state, setState] = useState<State>('confirming')
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
    void confirmAccessRequestAction(token).then((res) =>
      setState(res.success ? 'confirmed' : 'failed')
    )
  }, [])

  return (
    <div className="mx-auto flex w-full max-w-md flex-col items-center gap-4 text-center">
      {state === 'confirming' ? (
        <p className="flex items-center gap-2 text-sm text-muted-foreground" role="status">
          <Loader2 className="size-4 animate-spin" aria-hidden />
          {t('auth.requestAccess.confirming', 'Confirming your request...')}
        </p>
      ) : (
        <p className="text-sm" role="status">
          {state === 'confirmed'
            ? t(
                'auth.requestAccess.confirmed',
                'Your request is confirmed and waits for an administrator.'
              )
            : t('auth.requestAccess.confirmFailed', 'This link is invalid or has expired.')}
        </p>
      )}
      <Button asChild variant="outline">
        <Link href="/login">{t('auth.notSetUp.backToSignIn', 'Back to sign in')}</Link>
      </Button>
    </div>
  )
}
