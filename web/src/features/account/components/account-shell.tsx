'use client'

import Link from '@/components/link'
import { usePathname } from 'next/navigation'

import { BrandMark, usesBuiltInLogo } from '@/components/brand-logo'
import { LogoFull } from '@/assets/logo'
import { MainRegion } from '@/components/layout'
import { SkipToMain } from '@/components/skip-to-main'
import { StepUpDialogHost } from '@/components/step-up-dialog'
import { ThemeSwitch } from '@/components/theme-switch'
import { useBrand } from '@/context/brand-provider'
import { useTranslation } from '@/context/i18n-provider'
import { AccountSpaceProvider } from '@/context/account-space-provider'
import { cn } from '@/lib/utils'

import { AccountSignOut } from './account-sign-out'

const NAV = [
  { href: '/welcome', key: 'auth.welcome.nav.home', fallback: 'Home' },
  { href: '/account', key: 'auth.welcome.nav.profile', fallback: 'Profile' },
  { href: '/account/security', key: 'auth.welcome.nav.security', fallback: 'Security' },
  { href: '/account/preferences', key: 'auth.welcome.nav.preferences', fallback: 'Preferences' },
] as const

/**
 * The shell of a signed-in person with no organization (api RFC-141): the
 * brand, the four account pages, theme and sign out. No tenant sidebar, no
 * organization switcher, no search: every one of them reads organization data
 * the account-only session cannot reach.
 */
export function AccountShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const { t } = useTranslation()
  const brand = useBrand()

  return (
    <AccountSpaceProvider>
      <div className="flex min-h-svh flex-col bg-background">
        <SkipToMain />
        <header className="border-b bg-background">
          <div className="mx-auto flex w-full max-w-5xl flex-wrap items-center gap-x-6 gap-y-2 px-4 py-3 sm:px-6">
            <Link
              href="/welcome"
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
              aria-label={t('auth.welcome.navLabel', 'Account')}
              className="order-3 -mx-1 flex w-full gap-1 overflow-x-auto sm:order-none sm:mx-0 sm:w-auto sm:flex-1"
            >
              {NAV.map((item) => {
                const active = pathname === item.href
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    aria-current={active ? 'page' : undefined}
                    className={cn(
                      'rounded-md px-3 py-1.5 text-sm whitespace-nowrap transition-colors focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none',
                      active
                        ? 'bg-muted font-medium text-foreground'
                        : 'text-muted-foreground hover:bg-muted/60 hover:text-foreground'
                    )}
                  >
                    {t(item.key, item.fallback)}
                  </Link>
                )
              })}
            </nav>
            <div className="ms-auto flex items-center gap-2 sm:ms-0">
              <ThemeSwitch />
              <AccountSignOut />
            </div>
          </div>
        </header>
        <MainRegion className="mx-auto w-full max-w-5xl flex-1 px-4 py-6 sm:px-6">
          {children}
        </MainRegion>
        {/* Re-authentication prompt for sensitive actions (STEP_UP_REQUIRED). */}
        <StepUpDialogHost />
      </div>
    </AccountSpaceProvider>
  )
}
