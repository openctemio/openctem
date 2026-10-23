'use client'

import { Fragment, type ReactNode } from 'react'

import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'

/**
 * Where the operator's terms and privacy policy live (admin console, System >
 * Legal): documents hosted elsewhere or the built-in templates at /terms and
 * /privacy. The server pages pass them in (src/lib/legal.ts); the notice shows
 * only what is configured, so nothing links to a 404.
 */

interface LegalNoticeProps {
  /** What the visitor is doing: clicking sign in, or creating an account. */
  kind: 'signIn' | 'register'
  termsUrl?: string
  privacyUrl?: string
  className?: string
}

const linkClass = 'hover:text-primary underline underline-offset-4'

const FALLBACKS = {
  signIn: {
    both: 'By clicking sign in, you agree to our {terms} and {privacy}.',
    terms: 'By clicking sign in, you agree to our {terms}.',
    privacy: 'By clicking sign in, you agree to our {privacy}.',
  },
  register: {
    both: 'By creating an account, you agree to our {terms} and {privacy}.',
    terms: 'By creating an account, you agree to our {terms}.',
    privacy: 'By creating an account, you agree to our {privacy}.',
  },
} as const

/** "By <action>, you agree to our Terms of Service and Privacy Policy." */
export function LegalNotice({ kind, termsUrl = '', privacyUrl = '', className }: LegalNoticeProps) {
  const { t } = useTranslation()
  if (!termsUrl && !privacyUrl) return null

  const which = termsUrl && privacyUrl ? 'both' : termsUrl ? 'terms' : 'privacy'
  const links: Record<string, ReactNode> = {
    '{terms}': termsUrl ? (
      <a href={termsUrl} target="_blank" rel="noopener noreferrer" className={linkClass}>
        {t('auth.legal.terms', 'Terms of Service')}
      </a>
    ) : null,
    '{privacy}': privacyUrl ? (
      <a href={privacyUrl} target="_blank" rel="noopener noreferrer" className={linkClass}>
        {t('auth.legal.privacy', 'Privacy Policy')}
      </a>
    ) : null,
  }
  const text = t(`auth.legal.${kind}.${which}`, FALLBACKS[kind][which])

  return (
    <p className={cn('text-muted-foreground px-8 text-center text-sm', className)}>
      {text.split(/(\{terms\}|\{privacy\})/).map((part, i) => (
        <Fragment key={i}>{part in links ? links[part] : part}</Fragment>
      ))}
    </p>
  )
}
