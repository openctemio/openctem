'use client'

import Link from '@/components/link'
import { ArrowLeft } from 'lucide-react'
import { usePathname } from 'next/navigation'
import { useRef } from 'react'

import { BrandMark, usesBuiltInLogo } from '@/components/brand-logo'
import { LogoFull } from '@/assets/logo'
import { MainRegion } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { EDGE_FADE_X_CLASS, useTabStripScroll } from '@/components/ui/tabs'
import { SkipToMain } from '@/components/skip-to-main'
import { StepUpDialogHost } from '@/components/step-up-dialog'
import { ThemeSwitch } from '@/components/theme-switch'
import { useBrand } from '@/context/brand-provider'
import { useTranslation } from '@/context/i18n-provider'
import { AccountSpaceProvider } from '@/context/account-space-provider'
import { cn } from '@/lib/utils'
import { ACCOUNT_HOME_PATH } from '@/lib/middleware/config'
import { ACCOUNT_NAV, activeAccountItem } from '@/config/account-nav'

import { AccountSignOut } from './account-sign-out'
import { OwnershipInvitationBanner } from './ownership-invitation-banner'

/**
 * The shell of the account area, for anyone signed in (api RFC-141): the
 * brand, the account pages, a way back to the open organization, theme and
 * sign out. No tenant sidebar, no organization switcher, no search: every one
 * of them reads organization data, which the account area never shows.
 */
export function AccountShell({
  children,
  sessionReady = true,
  organizationName,
}: {
  children: React.ReactNode
  /**
   * The organization open in this browser, if any: the header offers a way
   * back to it. Undefined when none is open; '' when its name is unknown.
   */
  organizationName?: string
  /**
   * The account-only session exists. False on /welcome while it holds only a
   * refresh token: the hub starts the session and reloads, so nothing else
   * reads the API before that.
   */
  sessionReady?: boolean
}) {
  const pathname = usePathname()
  const { t } = useTranslation()
  const brand = useBrand()
  // The shared tab-strip behaviour: the open page's tab is scrolled into view
  // and an edge with hidden tabs fades, so no label is cut mid-word at rest.
  const navRef = useRef<HTMLElement>(null)
  useTabStripScroll(navRef)

  return (
    <AccountSpaceProvider>
      <div className="flex min-h-svh flex-col bg-background">
        <SkipToMain />
        <header className="border-b bg-background">
          <div className="mx-auto flex w-full max-w-5xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3 sm:px-6">
            <Link
              href={organizationName === undefined ? ACCOUNT_HOME_PATH : '/account'}
              className="flex items-center gap-2 rounded-md focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
            >
              {usesBuiltInLogo(brand) ? (
                <LogoFull className="h-[22px] w-auto shrink-0" />
              ) : (
                <>
                  <BrandMark size={28} className="size-7 shrink-0" />
                  <span className="text-lg leading-none font-semibold tracking-tight">
                    {brand.shortName}
                  </span>
                </>
              )}
            </Link>
            <nav
              ref={navRef}
              aria-label={t('account.area.navLabel', 'Your account')}
              className={cn(
                'no-scrollbar order-3 -mx-1 flex w-full gap-0.5 overflow-x-auto overscroll-x-contain lg:order-none lg:mx-0 lg:w-auto lg:flex-1',
                EDGE_FADE_X_CLASS
              )}
            >
              {ACCOUNT_NAV.map((item) => {
                const active = activeAccountItem(pathname)?.id === item.id
                return (
                  <Link
                    key={item.id}
                    href={item.url}
                    aria-current={active ? 'page' : undefined}
                    className={cn(
                      'rounded-md px-1.5 py-1.5 text-sm whitespace-nowrap transition-colors sm:px-3 focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
                      active
                        ? 'bg-muted font-medium text-foreground'
                        : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground'
                    )}
                  >
                    {t(`account.area.nav.${item.id}`, item.title)}
                  </Link>
                )
              })}
            </nav>
            <div className="ms-auto flex items-center gap-2 lg:ms-0">
              {organizationName !== undefined && (
                // The organization shell is another layout: it mounts its own
                // providers and reads its data afresh.
                <Button asChild variant="outline">
                  <Link href="/">
                    <ArrowLeft aria-hidden />
                    <span className="max-w-[16ch] truncate sm:max-w-[32ch]">
                      {organizationName
                        ? t('account.area.backTo', 'Back to {name}', { name: organizationName })
                        : t('account.area.backToOrganization', 'Back to your organization')}
                    </span>
                  </Link>
                </Button>
              )}
              <ThemeSwitch />
              <AccountSignOut />
            </div>
          </div>
        </header>
        <MainRegion className="mx-auto w-full max-w-5xl flex-1 px-4 py-6 sm:px-6">
          <OwnershipInvitationBanner className="mb-4" enabled={sessionReady} />
          {children}
        </MainRegion>
        {/* Re-authentication prompt for sensitive actions (STEP_UP_REQUIRED). */}
        <StepUpDialogHost />
      </div>
    </AccountSpaceProvider>
  )
}
