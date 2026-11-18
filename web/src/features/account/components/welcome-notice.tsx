'use client'

import { useTransition } from 'react'
import { AlertTriangle, Loader2, LogIn } from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { localLogoutAction } from '@/features/auth/actions/local-auth-actions'
import { ResendVerification } from '@/features/auth/components/resend-verification'
import type { WelcomeNotice as Notice } from '@/lib/auth/refresh-failure'

interface WelcomeNoticeProps {
  notice: Notice
  /** The organization that refused (a validated slug), when known. */
  org?: string
  email?: string
}

/**
 * Why the account space opened instead of the organization, with its one
 * next step: the organization's identity provider (signed out first, then
 * that organization's sign-in), the account's own sign-in (the session came
 * from another organization's identity provider), verifying the address, or
 * a work account.
 * A suspended organization has no step here: its administrator lifts it.
 */
export function WelcomeNotice({ notice, org, email }: WelcomeNoticeProps) {
  const { t } = useTranslation()
  const [pending, startTransition] = useTransition()
  const vars = { org: org ?? '' }
  const named = org ? 'Named' : ''

  const signOutTo = (href: string) =>
    startTransition(async () => {
      await localLogoutAction(href).catch(() => {
        window.location.href = href
      })
    })

  const action = (() => {
    switch (notice) {
      case 'sso_required':
      case 'idp_mfa_required':
        return org ? (
          <Button
            onClick={() => signOutTo(`/login?org=${encodeURIComponent(org)}`)}
            disabled={pending}
          >
            {pending ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : (
              <LogIn className="size-4" aria-hidden />
            )}
            {t('auth.welcome.notice.idpAction', undefined, vars)}
          </Button>
        ) : null
      case 'own_sign_in_required':
        return (
          <Button onClick={() => signOutTo('/login')} disabled={pending}>
            {pending ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : (
              <LogIn className="size-4" aria-hidden />
            )}
            {t('auth.welcome.notice.ownSignInAction')}
          </Button>
        )
      case 'personal_accounts_blocked':
        return (
          <Button onClick={() => signOutTo('/login')} disabled={pending}>
            {pending ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : (
              <LogIn className="size-4" aria-hidden />
            )}
            {t('auth.welcome.notice.workAccountAction')}
          </Button>
        )
      case 'email_not_verified':
        return <ResendVerification email={email} />
      default:
        return null
    }
  })()

  const key = {
    sso_required: 'sso',
    idp_mfa_required: 'idpMfa',
    organization_suspended: 'suspended',
    email_not_verified: 'emailNotVerified',
    personal_accounts_blocked: 'personalBlocked',
    own_sign_in_required: 'ownSignIn',
  }[notice]

  return (
    <Alert role="alert" data-testid="welcome-notice">
      <AlertTriangle className="size-4" aria-hidden />
      <AlertTitle>{t(`auth.welcome.notice.${key}Title${named}`, undefined, vars)}</AlertTitle>
      <AlertDescription className="flex flex-col items-start gap-3">
        <span>{t(`auth.welcome.notice.${key}Body`, undefined, vars)}</span>
        {action}
      </AlertDescription>
    </Alert>
  )
}
