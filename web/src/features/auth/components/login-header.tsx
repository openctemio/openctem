'use client'

import { CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useTranslation } from '@/context/i18n-provider'

import { SignUpPrompt } from './sign-up-prompt'

/** Heading of the sign-in page: its h1, the hint and the sign-up offer. */
export function LoginHeader({ returnTo, email }: { returnTo?: string | null; email?: string }) {
  const { t } = useTranslation()
  return (
    <CardHeader>
      <CardTitle className="text-lg tracking-tight">
        <h1>{t('auth.login.title', 'Sign in')}</h1>
      </CardTitle>
      <CardDescription>
        {t('auth.login.description', 'Enter your email and password to sign in to your account.')}
        {/* Sign-up is offered only when the server allows it, or when the
            visitor came from an invitation (accounts are otherwise created
            by an administrator). */}
        <SignUpPrompt returnTo={returnTo} email={email} />
      </CardDescription>
    </CardHeader>
  )
}
