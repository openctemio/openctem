'use client'

import { TextLink } from '@/components/ui/text-link'

import { useTranslation } from '@/context/i18n-provider'
import { useCanSelfRegister } from '../hooks/use-can-self-register'
import { registerHref } from '../lib/self-register'

interface SignUpPromptProps {
  /** Where the visitor goes after signing in (an invitation link allows sign-up). */
  returnTo?: string | null
  /** Email to pre-fill on the register form. */
  email?: string | null
}

/**
 * "Don't have an account? Sign up" — rendered only when the visitor may create
 * an account (open registration, or an invitation). Otherwise nothing.
 */
export function SignUpPrompt({ returnTo, email }: SignUpPromptProps) {
  const { canRegister } = useCanSelfRegister(returnTo)
  const { t } = useTranslation()
  if (!canRegister) return null
  return (
    <>
      {t('auth.signUp.prompt', "Don't have an account?")}{' '}
      <TextLink href={registerHref({ returnTo, email })} variant="inline">
        {t('auth.signUp.link', 'Sign up')}
      </TextLink>
    </>
  )
}
