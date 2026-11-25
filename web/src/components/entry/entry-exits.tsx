'use client'

import type { ReactNode } from 'react'
import { ArrowLeft } from 'lucide-react'

import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'

import { EntryActions, EntryCard, EntryHeader } from './entry-card'

/**
 * Where an entry page's way out leads: back to sign in (a visitor without a
 * session) or to the app (someone signed in, e.g. on an invitation or an
 * application consent page).
 */
export type EntryExit = 'signIn' | 'app'

/**
 * The one way back of every entry page, drawn the same everywhere: an outline
 * button with a back arrow, last in the card's actions. A page's main action
 * (send, reset, sign in now) stays the filled button above it.
 */
export function EntryBackLink({ to = 'signIn' }: { to?: EntryExit }) {
  const { t } = useTranslation()
  return (
    <Button variant="outline" asChild data-entry="back">
      <Link href={to === 'app' ? '/' : '/login'}>
        <ArrowLeft aria-hidden className="size-4 rtl:rotate-180" />
        {to === 'app'
          ? t('auth.entry.backToApp', 'Go to the dashboard')
          : t('auth.common.backToSignIn', 'Back to sign in')}
      </Link>
    </Button>
  )
}

export interface EntryLinkProblemProps {
  /** The problem itself, as the card title ("This reset link does not work"). */
  title: ReactNode
  /** What happened and what to do, in plain words. */
  description: ReactNode
  /** A way on, when there is one (request a new link): the filled button. */
  action?: ReactNode
  /** Anything the visitor can do in place, between the text and the actions. */
  children?: ReactNode
  exit?: EntryExit
}

/**
 * The state of an entry page whose link (reset, setup, verification,
 * confirmation, invitation) or request cannot be used: the title names the
 * problem, one plain description, at most one way on, then the way back.
 * Never a red banner under the page's normal title.
 */
export function EntryLinkProblem({
  title,
  description,
  action,
  children,
  exit = 'signIn',
}: EntryLinkProblemProps) {
  return (
    <EntryCard data-entry-state="link-problem">
      {/* A polite status: the problem often replaces a "checking..." card,
          and a screen reader hears the outcome without a red alert. */}
      <EntryHeader title={title} description={<span role="status">{description}</span>} />
      {children}
      <EntryActions>
        {action}
        <EntryBackLink to={exit} />
      </EntryActions>
    </EntryCard>
  )
}
