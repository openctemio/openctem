'use client'

import { createContext, useContext, useEffect, type ReactNode } from 'react'
import dynamic from 'next/dynamic'
import { Siren } from 'lucide-react'
import { usePathname, useRouter } from 'next/navigation'
import { toast } from 'sonner'
import { SidebarInset, SidebarProvider, SidebarTrigger } from '@/components/ui/sidebar'
import { Skeleton } from '@/components/ui/skeleton'
import { ThemeSwitch } from '@/components/theme-switch'
import { Search } from '@/components/search'
import { SearchProvider } from '@/context/search-provider'
import { useTranslation } from '@/context/i18n-provider'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { AdminConsoleSidebar } from './admin-console-sidebar'
import { ChangePasswordGate } from './change-password-gate'
import { localLogoutAction } from '@/features/auth/actions/local-auth-actions'
import { adminLogout, useAdminSession } from '../api/use-admin-session'
import type { AdminIdentity } from '../types'

const AdminContext = createContext<AdminIdentity | null>(null)

// Loaded the first time the palette opens, not with every console page.
const AdminCommandMenu = dynamic(
  () => import('./admin-command-menu').then((m) => m.AdminCommandMenu),
  { ssr: false }
)

/** The signed-in platform admin. Only valid inside AdminConsoleShell. */
export function useAdmin(): AdminIdentity {
  const admin = useContext(AdminContext)
  if (!admin) throw new Error('useAdmin must be used inside AdminConsoleShell')
  return admin
}

/**
 * Layout for every console page except verification. It owns the console
 * session: no valid session sends the browser to /admin/login, which asks for
 * the TOTP code (or, when not signed in, sends on to the normal /login). It deliberately has none
 * of the tenant shell's providers (TenantGate, bootstrap, permissions), since
 * an administrator has no tenant.
 */
export function AdminConsoleShell({ children }: { children: ReactNode }) {
  const { admin, isLoading, error } = useAdminSession()
  const pathname = usePathname()
  const router = useRouter()
  const { t } = useTranslation()

  useEffect(() => {
    if (!isLoading && !error && admin === null) {
      router.replace(`/admin/login?next=${encodeURIComponent(pathname)}`)
    }
  }, [admin, isLoading, error, pathname, router])

  const signOut = async () => {
    try {
      // Ends the console session and the /login session it was opened from.
      await adminLogout()
    } catch {
      toast.error('Sign-out failed; the session will still expire on its own.')
    }
    // Clears the /login cookies and navigates (a full load, so no cached
    // console response survives).
    await localLogoutAction('/login')
  }

  if (error) {
    return (
      <div className="flex min-h-svh items-center justify-center p-6 text-center text-sm text-muted-foreground">
        The console could not reach the API. Refresh to try again.
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

  return (
    <AdminContext.Provider value={admin}>
      <SearchProvider menu={AdminCommandMenu}>
        <SidebarProvider>
          <AdminConsoleSidebar admin={admin} onSignOut={signOut} />
          <SidebarInset>
            {/* One header for every width: the sidebar trigger only on small
              screens, then the console search (Cmd/Ctrl+K) and the theme. */}
            <header className="flex h-14 shrink-0 items-center gap-2 px-4">
              <SidebarTrigger variant="outline" className="md:hidden" />
              <span className="text-sm font-medium md:hidden">
                {t('admin.shell.title', 'Platform administration')}
              </span>
              <div className="ms-auto flex items-center gap-2">
                <Search placeholder={t('admin.shell.search', 'Search the console')} />
                <ThemeSwitch />
              </div>
            </header>
            {/* A div, not <main>: every page renders <Main>, which is the landmark. */}
            <div id="content" className="min-h-0 flex-1 overflow-y-auto">
              {admin.is_break_glass && (
                <div className="px-4 pt-2">
                  <Alert variant="destructive">
                    <Siren className="size-4" />
                    <AlertTitle>Break-glass session</AlertTitle>
                    <AlertDescription>
                      You signed in with an emergency-access account. Every other administrator was
                      alerted. Use it only to restore normal access, then sign out.
                    </AlertDescription>
                  </Alert>
                </div>
              )}
              {children}
            </div>
          </SidebarInset>
        </SidebarProvider>
      </SearchProvider>
    </AdminContext.Provider>
  )
}
