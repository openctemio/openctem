'use client'

import { useCallback } from 'react'

import { useTranslation } from '@/context/i18n-provider'
import { getCookie } from '@/lib/cookies'
import { env } from '@/lib/env'
import { validateRedirectUrl } from '@/lib/redirect'

import { localLogoutAction } from '../actions/local-auth-actions'
import { MfaSessionStep } from './mfa-session-step'

/** The organization the person was in, from the (JS-readable) tenant cookie. */
function currentTenantId(): string | undefined {
  const raw = getCookie(env.cookies.tenant)
  if (!raw) return undefined
  try {
    const id = (JSON.parse(raw) as { id?: unknown }).id
    return typeof id === 'string' && id ? id : undefined
  } catch {
    return undefined
  }
}

/**
 * Full-page two-factor setup for a signed-in session an organization holds
 * back. On completion the tenant token is minted again and the person returns
 * to the page they were on. A gone session goes to sign-in with the reason.
 */
export function TwoFactorSetup({ next }: { next?: string }) {
  const { t } = useTranslation()
  const target = validateRedirectUrl(next, '/')

  const onComplete = useCallback(() => {
    window.location.href = target
  }, [target])

  const onSessionExpired = useCallback(() => {
    const params = new URLSearchParams({ reason: 'mfa_required' })
    if (target !== '/') params.set('returnTo', target)
    const login = `/login?${params.toString()}`
    // Drop the dead session cookies first: /login treats a cookie as signed in.
    localLogoutAction(login).catch(() => {
      window.location.href = login
    })
  }, [target])

  return (
    <div className="grid gap-4">
      <div className="space-y-1">
        <h1 className="text-lg font-semibold">
          {t('auth.mfaSession.pageTitle', 'Set up two-factor authentication')}
        </h1>
        <p className="text-sm text-muted-foreground">
          {t(
            'auth.mfaSession.pageBody',
            'Your organization now requires two-factor authentication. Set it up to keep working; you stay signed in.'
          )}
        </p>
      </div>
      <MfaSessionStep
        tenantId={currentTenantId()}
        onComplete={onComplete}
        onSessionExpired={onSessionExpired}
        onReauthRequired={onSessionExpired}
      />
    </div>
  )
}
