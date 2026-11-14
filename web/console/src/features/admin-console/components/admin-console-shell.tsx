'use client'

import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import dynamic from 'next/dynamic'
import { Siren } from 'lucide-react'
import { usePathname, useRouter } from 'next/navigation'
import { toast } from 'sonner'
import { SidebarInset, SidebarProvider } from '@/components/ui/sidebar'
import { Skeleton } from '@/components/ui/skeleton'
import { ThemeSwitch } from '@/components/theme-switch'
import { Search } from '@/components/search'
import { FullscreenToggle } from '@/components/fullscreen-toggle'
import { SkipToMain } from '@/components/skip-to-main'
import { Header } from '@/components/layout/app-header'
import { HEADER_ACTIONS_GROUP } from '@/components/layout/header-controls'
import { SearchProvider } from '@/context/search-provider'
import { useTranslation } from '@/context/i18n-provider'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { AdminApprovalPrompt } from './admin-approval-prompt'
import { AdminStepUpPrompt } from './admin-step-up-prompt'
import { AdminElevationBar } from './admin-elevation-bar'
import { AdminConsoleSidebar } from './admin-console-sidebar'
import { ChangePasswordGate } from './change-password-gate'
import { FactorEnrollmentGate } from './factor-enrollment-gate'
import { VersionCheckBanner } from './version-check-banner'
import { ElevationRequestContext } from './elevation-request'
import { adminLogout, useAdminSession } from '../api/use-admin-session'
import { setAdminEnrollmentListener } from '@console/lib/admin-api/client'
import { adminCanElevate, type AdminIdentity } from '../types'
import { visibleAdminNav } from '../lib/admin-nav-visibility'
import { consoleCrumbLevels } from '../lib/console-crumbs'

const AdminContext = createContext<AdminIdentity | null>(null)

// Loaded the first time the palette opens, not with every console page.
const AdminCommandMenu = dynamic(
  () => import('./admin-command-menu').then((m) => m.AdminCommandMenu),
  { ssr: false }
)

/** The signed-in platform admin, or null outside AdminConsoleShell. */
export function useAdminOrNull(): AdminIdentity | null {
  return useContext(AdminContext)
}

/** The signed-in platform admin. Only valid inside AdminConsoleShell. */
export function useAdmin(): AdminIdentity {
  const admin = useContext(AdminContext)
  if (!admin) throw new Error('useAdmin must be used inside AdminConsoleShell')
  return admin
}

/**
 * Layout for every console page except verification. It owns the console
 * session: no valid session sends the browser to the console's /login (its
 * own email, password and second factor). It deliberately has none
 * of the tenant shell's providers (TenantGate, bootstrap, permissions), since
 * an administrator has no tenant.
 */
export function AdminConsoleShell({ children }: { children: ReactNode }) {
  const { admin, isLoading, error, mutate } = useAdminSession()
  const pathname = usePathname()
  const router = useRouter()
  const { t } = useTranslation()
  const [elevateOpen, setElevateOpen] = useState(false)

  useEffect(() => {
    if (!isLoading && !error && admin === null) {
      router.replace(`/login?next=${encodeURIComponent(pathname)}`)
    }
  }, [admin, isLoading, error, pathname, router])

  // Any console call refused with FACTOR_ENROLLMENT_REQUIRED re-reads the
  // session, which then carries factor_enrollment_required and shows the gate.
  useEffect(() => {
    setAdminEnrollmentListener(() => void mutate())
    return () => setAdminEnrollmentListener(null)
  }, [mutate])

  const signOut = async () => {
    try {
      // Ends the console session only: the console has its own sign-in.
      await adminLogout()
    } catch {
      toast.error(
        t('admin.shell.signOutFailed', 'Sign-out failed; the session will still expire on its own.')
      )
    }
    // A full load, so no cached console response survives.
    window.location.replace('/login')
  }

  if (error) {
    return (
      <div className="flex min-h-svh items-center justify-center p-6 text-center text-sm text-muted-foreground">
        {t('admin.shell.unreachable', 'The console could not reach the API. Refresh to try again.')}
      </div>
    )
  }
  if (isLoading || !admin) {
    return (
      <div className="flex min-h-svh gap-4 p-4">
        <Skeleton className="hidden h-full w-60 md:block" />
        <div className="flex-1 space-y-3">
          <Skeleton className="h-10 w-1/3" />
          <Skeleton className="h-64 w-full" />
        </div>
      </div>
    )
  }

  // The API refuses every other console call until the temporary password is
  // changed; show only the change form.
  if (admin.password_change_required) {
    return <ChangePasswordGate admin={admin} />
  }

  // "Require security keys" holds this administrator on enrollment: only the
  // security-keys page works until they comply.
  if (admin.factor_enrollment_required) {
    return (
      <FactorEnrollmentGate
        admin={admin}
        onChanged={() => void mutate()}
        onSignOut={() => void signOut()}
      />
    )
  }

  // A read-only session of an administrator who may elevate: pages offer the
  // elevate dialog next to what it unlocks.
  const canElevate = adminCanElevate(admin)
  const requestElevation = canElevate ? () => setElevateOpen(true) : null

  // The breadcrumb names pages as the sidebar does (the same visible items).
  const visible = visibleAdminNav(admin)
  const overview = visible.flatMap((s) => s.items).find((i) => i.url === '/')
  const crumbs = {
    homeLabel: overview ? t(overview.i18nKey, overview.title) : t('admin.crumb.home', 'Overview'),
    levels: consoleCrumbLevels(
      pathname,
      visible,
      (item) => t(item.i18nKey, item.title),
      (listUrl) =>
        listUrl === '/organizations'
          ? t('admin.crumb.organization', 'Organization')
          : listUrl === '/users'
            ? t('admin.crumb.user', 'User')
            : t('admin.crumb.record', 'Details')
    ),
  }

  return (
    <AdminContext.Provider value={admin}>
      <ElevationRequestContext.Provider value={requestElevation}>
        <SearchProvider menu={AdminCommandMenu}>
          <SidebarProvider>
            {/* First focusable element: keyboard users skip the navigation
                (the tenant app's skip link, to #content below). */}
            <SkipToMain />
            <AdminConsoleSidebar admin={admin} onSignOut={signOut} />
            <SidebarInset>
              {/* The tenant app's top bar (shell package 0.2, console variant): the
                  breadcrumb from the console navigation, the console search
                  (Ctrl/Cmd+K), then Full screen, Theme and the elevation control.
                  Below 768 px the phone bar: sidebar toggle, title, search, theme,
                  elevation. */}
              <Header showHeaderActions={false} crumbs={crumbs}>
                <Search
                  className="ms-auto shrink-0"
                  placeholder={t('admin.shell.search', 'Search the console')}
                />
                <div className={HEADER_ACTIONS_GROUP} data-slot="header-actions">
                  <FullscreenToggle />
                  <ThemeSwitch />
                  {/* Read-only or elevated, always in view, one line high. */}
                  <AdminElevationBar
                    admin={admin}
                    onChanged={() => void mutate()}
                    open={elevateOpen}
                    onOpenChange={setElevateOpen}
                  />
                </div>
              </Header>
              {/* A div, not <main>: every page renders <Main>, which is the landmark. */}
              {/* The page scrolls inside this box, so it takes keyboard focus: a page with
                  nothing interactive (a read-only list on a phone) still scrolls with the
                  arrow keys. */}
              <div
                id="content"
                role="region"
                aria-label={t('admin.shell.contentRegion', 'Page content')}
                tabIndex={0}
                className="min-h-0 flex-1 overflow-y-auto focus:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset"
              >
                {admin.is_break_glass && (
                  <div className="px-4 pt-2">
                    <Alert variant="destructive">
                      <Siren className="size-4" />
                      <AlertTitle>
                        {t('admin.shell.breakGlassTitle', 'Break-glass session')}
                      </AlertTitle>
                      <AlertDescription>
                        {t(
                          'admin.shell.breakGlassBody',
                          'You signed in with an emergency-access account. Every other administrator was alerted. Use it only to restore normal access, then sign out.'
                        )}
                      </AlertDescription>
                    </Alert>
                  </div>
                )}
                <VersionCheckBanner />
                {children}
              </div>
              <AdminStepUpPrompt />
              <AdminApprovalPrompt />
            </SidebarInset>
          </SidebarProvider>
        </SearchProvider>
      </ElevationRequestContext.Provider>
    </AdminContext.Provider>
  )
}
