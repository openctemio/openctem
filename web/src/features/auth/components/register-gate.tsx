'use client'

import Link from '@/components/link'
import { useSearchParams } from 'next/navigation'
import { ArrowLeft } from 'lucide-react'

import { EntryActions, EntryCard, EntryHeader, EntryLine, EntryNote } from '@/components/entry'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { TextLink } from '@/components/ui/text-link'

import { useTranslation } from '@/context/i18n-provider'
import { safeHref } from '@/lib/safe-href'
import { useCanSelfRegister } from '../hooks/use-can-self-register'
import { LegalNotice } from './legal-notice'
import { RegisterForm } from './register-form'

/**
 * The /register page body. Shows the sign-up form only when the server allows
 * open registration or the visitor holds an invitation; otherwise explains that
 * accounts are created by an administrator.
 */
export function RegisterGate({
  termsUrl,
  privacyUrl,
}: {
  /** The operator's legal documents (from the server environment). */
  termsUrl?: string
  privacyUrl?: string
} = {}) {
  const searchParams = useSearchParams()
  const returnTo = searchParams.get('returnTo')
  const { canRegister, isLoading } = useCanSelfRegister(returnTo)
  const { t } = useTranslation()

  if (isLoading) {
    return (
      <EntryCard aria-busy="true">
        <div className="flex flex-col gap-1">
          <Skeleton className="h-8 w-40" />
          <Skeleton className="h-5 w-64 max-w-full" />
        </div>
        <Skeleton className="h-control w-full" />
        <Skeleton className="h-control w-full" />
        <Skeleton className="h-control w-full" />
      </EntryCard>
    )
  }

  if (!canRegister) {
    return (
      <EntryCard>
        <EntryHeader
          title={t('auth.register.disabledTitle', 'Registration is disabled')}
          description={t(
            'auth.register.disabledBody',
            'Accounts are created by your administrator. If you were given a setup or invitation link, open it to get started.'
          )}
        />
        <EntryActions>
          <Button variant="outline" asChild>
            <Link href="/login">
              <ArrowLeft aria-hidden className="size-4" />
              {t('auth.common.backToSignIn', 'Back to sign in')}
            </Link>
          </Button>
        </EntryActions>
      </EntryCard>
    )
  }

  const loginHref = returnTo ? `/login?returnTo=${encodeURIComponent(returnTo)}` : '/login'

  return (
    <EntryCard>
      <EntryHeader
        title={t('auth.register.title', 'Create an account')}
        description={t(
          'auth.register.description',
          'Enter your email and password to create an account.'
        )}
      />
      <RegisterForm />
      <EntryNote>
        <LegalNotice kind="register" termsUrl={termsUrl} privacyUrl={privacyUrl} />
      </EntryNote>
      <EntryLine>
        {t('auth.register.haveAccount', 'Already have an account?')}{' '}
        <TextLink href={safeHref(loginHref)} variant="inline">
          {t('auth.register.signIn', 'Sign in')}
        </TextLink>
      </EntryLine>
    </EntryCard>
  )
}
