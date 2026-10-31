import { cookies } from 'next/headers'
import { cn } from '@/lib/utils'
import { LayoutProvider } from '@/context/layout-provider'
import { SearchProvider } from '@/context/search-provider'
import { SidebarInset, SidebarProvider } from '@/components/ui/sidebar'
import {
  DashboardHeader,
  DashboardProviders,
  AppSidebar,
  TenantGate,
  MainRegion,
} from '@/components/layout'
import { SkipToMain } from '@/components/skip-to-main'
import { RouteGuard } from '@/components/route-guard'
import { StepUpDialogHost } from '@/components/step-up-dialog'
import { SettingsAnchorHighlighter } from '@/components/layout/settings-anchor-highlighter'
import { PlatformAnnouncementBanner } from '@/features/announcements/components/platform-announcement-banner'
import { SupportAccessBanner } from '@/features/support-access/components/support-access-banner'
import { PendingLinkPrompt } from '@/features/account/components/pending-link-prompt'
import { pendingLinkCookieName } from '@/features/auth/lib/oauth-cookies'

type SiteLayoutProps = {
  children?: React.ReactNode
}

export default async function SiteLayout({ children }: SiteLayoutProps) {
  // Read sidebar state from cookie on server side
  const cookieStore = await cookies()
  const sidebarState = cookieStore.get('sidebar_state')?.value
  const defaultOpen = sidebarState !== 'false'
  // A refused social sign-in left a pending link: ask to confirm it.
  const hasPendingLink = !!cookieStore.get(pendingLinkCookieName())?.value
  return (
    <DashboardProviders>
      <SearchProvider>
        <LayoutProvider>
          {/* TenantGate checks if user has tenants */}
          {/* If no tenants: shows Create Team page without sidebar */}
          {/* If has tenants: shows normal dashboard layout */}
          <TenantGate>
            <SidebarProvider defaultOpen={defaultOpen}>
              <SkipToMain />
              <AppSidebar />
              <SidebarInset
                className={cn(
                  // Set content container, so we can use container queries
                  '@container/content',

                  // If layout is fixed, set the height
                  // to 100svh to prevent overflow
                  'has-[[data-layout=fixed]]:h-svh'
                )}
              >
                {/* RouteGuard checks if user has permission to access current route */}
                {/* Shows "Access Denied" page if user doesn't have required permission */}
                <RouteGuard>
                  {/* Global header that handles per-route visibility */}
                  <DashboardHeader />
                  {/* The platform operator's notices (maintenance, warnings). */}
                  <PlatformAnnouncementBanner />
                  {/* Platform support can read this organization's data now (RFC-063). */}
                  <SupportAccessBanner />
                  {/*
                    `flex flex-1 flex-col` propagates the flex context
                    from SidebarInset (which is `flex flex-col flex-1`)
                    down into the page. Without this, any page that uses
                    <Main fixed> (full-viewport builders: scan workflow editor,
                    automation builder, dashboards with side panels) has no
                    flex parent to grow into → `flex-grow` collapses →
                    canvas renders at content height and scrolls mid-page.
                    The overflow-hidden scope is gated by data-layout=fixed
                    so "normal" pages still scroll naturally at the body.
                  */}
                  {/* The page's one `main` landmark: a page's own <Main> inside
                      it renders as a plain container. */}
                  <MainRegion className="min-h-0 flex-1 overflow-y-auto overscroll-contain has-[[data-layout=fixed]]:flex has-[[data-layout=fixed]]:flex-col has-[[data-layout=fixed]]:overflow-hidden">
                    {children}
                  </MainRegion>
                </RouteGuard>
              </SidebarInset>
            </SidebarProvider>
          </TenantGate>
          {/* Re-authentication prompt for sensitive actions (STEP_UP_REQUIRED). */}
          <StepUpDialogHost />
          {hasPendingLink && <PendingLinkPrompt />}
          <SettingsAnchorHighlighter />
        </LayoutProvider>
      </SearchProvider>
    </DashboardProviders>
  )
}
