'use client'

import type { ReactNode } from 'react'
import { Languages } from 'lucide-react'

import { BrandLogoFull, PoweredBy } from '@/components/brand-logo'
import { LocaleMenuItems } from '@/components/language-switcher'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { TextLink } from '@/components/ui/text-link'
import { useTranslation } from '@/context/i18n-provider'
import { Overridable } from '@/lib/extension/overridable'
import { safeHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'

/**
 * The frame of every page without the app shell (sign-in, sign-up, password
 * and e-mail links, two-factor, organization choice, onboarding, invitations,
 * application consent): the brand, the page's card(s) in one column of a fixed
 * width, then one footer line with the legal links, the "powered by" notice
 * and the language switch. Controls inside are 36px (`data-control-scale`).
 *
 * Below 640px the column is the screen: cards lose their border and padding
 * (see EntryCard) and the page starts under a taller top gap that clears the
 * notch. The frame holds no state and reads nothing: a page's requests,
 * redirects and cookies are untouched by it.
 */
export interface EntryFrameProps {
  children: ReactNode
  /** The operator's terms and privacy links; a link shows only when set. */
  termsUrl?: string
  privacyUrl?: string
  /** `wide` for a page that lists things (invitations, organizations hub). */
  width?: 'card' | 'wide'
  className?: string
}

export function EntryFrame({
  children,
  termsUrl = '',
  privacyUrl = '',
  width = 'card',
  className,
}: EntryFrameProps) {
  const { t } = useTranslation()
  return (
    <div
      data-control-scale="entry"
      data-slot="entry-frame"
      className={cn(
        'flex min-h-svh flex-col items-center gap-4 px-4 pb-6 pt-[max(3rem,env(safe-area-inset-top))] sm:gap-5 sm:pt-8',
        className
      )}
    >
      <header className="flex w-full justify-start sm:justify-center">
        <Link
          href="/login"
          aria-label={t('auth.entry.brandLink', 'Go to sign in')}
          className="text-foreground rounded-sm p-1.5"
        >
          <BrandLogoFull className="h-8 w-auto" />
        </Link>
      </header>
      <main
        id="main-content"
        data-slot="entry-main"
        className={cn(
          'flex w-full flex-col gap-4',
          width === 'wide' ? 'max-w-entry-wide' : 'max-w-entry'
        )}
      >
        {children}
      </main>
      <footer
        data-slot="entry-footer"
        className="text-cap text-muted-foreground mt-auto flex w-full flex-wrap items-center justify-center gap-x-4 gap-y-1 sm:mt-0"
      >
        {termsUrl && (
          <TextLink href={safeHref(termsUrl)} external={!termsUrl.startsWith('/')}>
            {t('auth.legal.terms', 'Terms of Service')}
          </TextLink>
        )}
        {privacyUrl && (
          <TextLink href={safeHref(privacyUrl)} external={!privacyUrl.startsWith('/')}>
            {t('auth.legal.privacy', 'Privacy Policy')}
          </TextLink>
        )}
        <Overridable id="auth.footer" fallback={PoweredBy} />
        <EntryLanguageSwitch />
      </footer>
    </div>
  )
}

/** The language menu of the footer: the same cookie and reload as the app's. */
function EntryLanguageSwitch() {
  const { t } = useTranslation()
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" data-slot="entry-language">
          <Languages aria-hidden />
          {t('common.language', 'Language')}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="center">
        <LocaleMenuItems />
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
