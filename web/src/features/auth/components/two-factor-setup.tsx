'use client'

import { useCallback, useState } from 'react'

import { EntryHeader } from '@/components/entry'
import { useTranslation } from '@/context/i18n-provider'
import { navigateAfterSessionChange } from '@/lib/session-navigation'
import { getCookie } from '@/lib/cookies'
import { env } from '@/lib/env'
import { validateRedirectUrl } from '@/lib/redirect'

import { localLogoutAction, type MfaPurpose } from '../actions/local-auth-actions'
import { MfaSessionStep } from './mfa-session-step'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

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
export function TwoFactorSetup({ next, org }: { next?: string; org?: string }) {
  const { t } = useTranslation()
  const target = validateRedirectUrl(next, '/')
  // The organization to open afterwards: the one named by the page that sent
  // the person here (an invitation just accepted, a sign-in landing), else the
  // one they were in. The API checks the membership and the rule on the
  // exchange; the id is never trusted on its own.
  const tenantId = org && UUID.test(org) ? org : currentTenantId()

  // Unknown until the API answers: a person who already has 2FA on is asked
  // only for a code, so the heading must not tell them to set it up.
  const [purpose, setPurpose] = useState<MfaPurpose>()

  const onComplete = useCallback(() => {
    navigateAfterSessionChange(target)
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
    <>
      {purpose === 'verify' ? (
        <EntryHeader
          title={t('auth.mfaSession.verifyPageTitle', 'Confirm two-factor authentication')}
          description={t(
            'auth.mfaSession.verifyPageBody',
            'Your organization requires two-factor authentication, and yours is already on. Enter a code to keep working; you stay signed in.'
          )}
        />
      ) : purpose === 'enroll' ? (
        <EntryHeader
          title={t('auth.mfaSession.pageTitle', 'Set up two-factor authentication')}
          description={t(
            'auth.mfaSession.pageBody',
            'Your organization now requires two-factor authentication. Set it up to keep working; you stay signed in.'
          )}
        />
      ) : (
        <EntryHeader title={t('auth.mfa.title', 'Two-factor authentication')} />
      )}
      <MfaSessionStep
        onPurpose={setPurpose}
        tenantId={tenantId}
        onComplete={onComplete}
        onSessionExpired={onSessionExpired}
        onReauthRequired={onSessionExpired}
      />
    </>
  )
}
