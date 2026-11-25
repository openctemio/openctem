'use client'

import { useEffect, useRef, useState } from 'react'
import Link from '@/components/link'
import { Loader2 } from 'lucide-react'
import {
  EntryActions,
  EntryBackLink,
  EntryBanner,
  EntryCard,
  EntryHeader,
  EntryLinkProblem,
} from '@/components/entry'
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

  if (state === 'failed') {
    return (
      <EntryLinkProblem
        title={t('auth.requestAccess.confirmFailedTitle', 'This confirmation link does not work')}
        description={t(
          'auth.requestAccess.confirmFailedBody',
          'It may have expired or been used already. Send a new request.'
        )}
        action={
          <Button asChild variant="signal">
            <Link href="/request-access">
              {t('auth.requestAccess.newRequest', 'Send a new request')}
            </Link>
          </Button>
        }
      />
    )
  }

  return (
    <EntryCard>
      <EntryHeader title={t('auth.requestAccess.title', 'Request access')} />
      {state === 'confirming' ? (
        <p className="text-body text-muted-foreground flex items-center gap-2" role="status">
          <Loader2 className="size-4 animate-spin" aria-hidden />
          {t('auth.requestAccess.confirming', 'Confirming your request...')}
        </p>
      ) : (
        <EntryBanner tone="ok" role="status">
          {t(
            'auth.requestAccess.confirmed',
            'Your request is confirmed and waits for an administrator.'
          )}
        </EntryBanner>
      )}
      <EntryActions>
        <EntryBackLink />
      </EntryActions>
    </EntryCard>
  )
}
