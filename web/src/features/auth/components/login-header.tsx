'use client'

import { EntryHeader } from '@/components/entry'
import { useTranslation } from '@/context/i18n-provider'

/** Heading of the sign-in page: its h1 and the hint. */
export function LoginHeader() {
  const { t } = useTranslation()
  return (
    <EntryHeader
      title={t('auth.login.title', 'Sign in')}
      description={t(
        'auth.login.description',
        'Enter your email and password to sign in to your account.'
      )}
    />
  )
}
