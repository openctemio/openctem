'use client'

import { useEffect, useState } from 'react'
import { usePathname } from 'next/navigation'
import { ArrowLeft, Fingerprint, LogOut, Settings, ShieldCheck } from 'lucide-react'
import Link from '@/components/link'
import {
  Sidebar,
  SidebarContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  useSidebarActions,
} from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import {
  SidebarBrand,
  SIDEBAR_CHIP_CLASS,
  SIDEBAR_CONTEXT_ROW_CLASS,
} from '@/components/layout/sidebar-brand'
import { cn } from '@/lib/utils'
import { GroupedNav, type GroupedNavSection } from '@/components/layout/grouped-nav'
import { NAV_BUTTON_CLASS, NAV_COLUMN_CLASS } from '@/components/layout/nav-group'
import { NavPendingHint, SidebarLink } from '@/components/layout/sidebar-link'
import { SidebarFooterLinks } from '@/components/layout/sidebar-footer-links'
import { ADMIN_API_VERSION_PATH, setAdminApiVersionFetcher } from '@/hooks/use-build-versions'
import { adminFetch } from '@console/lib/admin-api/client'
import { useTranslation } from '@/context/i18n-provider'
import { ConsoleLanguagePicker } from './console-language-picker'
import { safeConsolePath } from '../lib/console-navigation'
import {
  activeNavUrl,
  isSettingsRailPath,
  mainNavSections,
  settingsRailSections,
  visibleAdminNav,
} from '../lib/admin-nav-visibility'
import type { AdminNavSection } from '../config/admin-nav'
import { actingRoleLabel, type AdminIdentity } from '../types'

// Help > About reads the API's build through the console's own API proxy.
setAdminApiVersionFetcher(() => adminFetch<unknown>(ADMIN_API_VERSION_PATH))

const RETURN_KEY = 'openctem.admin.settings-return-to'

/**
 * The last console page outside the settings rail, so "Back to console"
 * returns there instead of always to the overview. Per tab, best effort.
 */
function useConsoleReturnPath(onRail: boolean): string {
  const pathname = usePathname()
  const [back, setBack] = useState('/')
  useEffect(() => {
    try {
      if (!onRail) {
        sessionStorage.setItem(RETURN_KEY, pathname + window.location.search)
        return
      }
      // Only a same-origin console path (safeConsolePath), never another site.
      setBack(safeConsolePath(sessionStorage.getItem(RETURN_KEY)))
    } catch {
      // Storage blocked: back goes to the overview.
    }
  }, [onRail, pathname])
  return back
}

interface AdminConsoleSidebarProps {
  admin: AdminIdentity
  onSignOut: () => void
}

/**
 * Console sidebar: the shared brand row, then a fixed "Platform administration"
 * context row (with what the session acts as) where the tenant shell has its
 * organization switcher, then the console navigation and the signed-in admin.
 * On a settings page the navigation is the settings rail, led by "Back to
 * console", the same model as the tenant app's settings shell.
 */
export function AdminConsoleSidebar({ admin, onSignOut }: AdminConsoleSidebarProps) {
  const pathname = usePathname()
  const { t } = useTranslation()
  // By the administrator's own role, not the session's acting one: a super
  // admin acting read-only still sees every page, and the page offers the
  // elevation next to what it unlocks.
  const visible = visibleAdminNav(admin)
  const onRail = isSettingsRailPath(pathname, visible)
  const backHref = useConsoleReturnPath(onRail)
  const { setOpenMobile } = useSidebarActions()
  const toGrouped = (list: AdminNavSection[]): GroupedNavSection[] =>
    list.map((section, i) => ({
      key: section.title ?? String(i),
      label: section.i18nKey ? t(section.i18nKey, section.title) : section.title,
      items: section.items
        .filter((item) => !item.hideInSidebar)
        .map((item) => ({
          key: item.url,
          title: t(item.i18nKey, item.title),
          url: item.url,
          icon: item.icon,
        })),
    }))
  const rail = settingsRailSections(visible)
  // The main sidebar ends with one Settings entry that opens the first
  // settings page the administrator may see; on any settings page the
  // sidebar shows the rail instead.
  const settingsUrl = rail[0]?.items[0]?.url
  const sections: GroupedNavSection[] = onRail
    ? toGrouped(rail)
    : [
        ...toGrouped(mainNavSections(visible)),
        ...(settingsUrl
          ? [
              {
                key: 'settings',
                items: [
                  {
                    key: settingsUrl,
                    title: t('admin.nav.group.settings', 'Settings'),
                    url: settingsUrl,
                    icon: Settings,
                  },
                ],
              },
            ]
          : []),
      ]
  const activeUrl = activeNavUrl(pathname, visible)
  const backLabel = t('admin.nav.settings.back', 'Back to console')
  const role = actingRoleLabel(admin)

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="gap-3">
        <SidebarBrand href="/" />
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              className={cn(SIDEBAR_CONTEXT_ROW_CLASS, 'pointer-events-none h-10')}
              tooltip={t('admin.shell.contextRow', 'Platform administration')}
            >
              <div className={SIDEBAR_CHIP_CLASS}>
                <ShieldCheck className="size-4" />
              </div>
              <div className="grid flex-1 text-start text-sm leading-tight">
                <span className="truncate font-semibold">
                  {t('admin.shell.contextRow', 'Platform administration')}
                </span>
                <span className="truncate text-xs text-muted-foreground">
                  {t(role.key, role.fallback)}
                </span>
              </div>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
        <Separator orientation="horizontal" className="mt-1" />
      </SidebarHeader>

      <SidebarContent>
        <nav
          aria-label={
            onRail
              ? t('admin.nav.group.settings', 'Settings')
              : t('admin.nav.label', 'Console navigation')
          }
          className={NAV_COLUMN_CLASS}
        >
          {onRail && (
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton asChild tooltip={backLabel} className={NAV_BUTTON_CLASS}>
                  <SidebarLink href={backHref} onClick={() => setOpenMobile(false)}>
                    <ArrowLeft className="rtl:rotate-180" />
                    <span>
                      {backLabel}
                      <NavPendingHint />
                    </span>
                  </SidebarLink>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          )}
          <GroupedNav sections={sections} activeUrl={activeUrl} />
        </nav>
      </SidebarContent>

      {/* The tenant app's footer (Help; an admin has no tenant Settings), with
          the signed-in admin and sign-out under it. */}
      <SidebarFooterLinks shell="admin">
        <SidebarMenuItem>
          <div className="grid px-2 py-1 text-sm leading-tight group-data-[collapsible=icon]:hidden">
            <span className="truncate font-medium">{admin.name}</span>
            <span className="truncate text-xs text-muted-foreground">{admin.email}</span>
          </div>
        </SidebarMenuItem>
        <SidebarMenuItem>
          <SidebarMenuButton
            asChild
            isActive={pathname === '/security/keys'}
            tooltip={t('admin.nav.securityKeys', 'My security keys')}
            className={NAV_BUTTON_CLASS}
          >
            <Link href="/security/keys">
              <Fingerprint />
              <span>{t('admin.nav.securityKeys', 'My security keys')}</span>
            </Link>
          </SidebarMenuButton>
        </SidebarMenuItem>
        <SidebarMenuItem>
          <ConsoleLanguagePicker />
        </SidebarMenuItem>
        <SidebarMenuItem>
          <SidebarMenuButton
            onClick={onSignOut}
            tooltip={t('admin.shell.signOut', 'Sign out')}
            className={NAV_BUTTON_CLASS}
          >
            <LogOut />
            <span>{t('admin.shell.signOut', 'Sign out')}</span>
          </SidebarMenuButton>
        </SidebarMenuItem>
      </SidebarFooterLinks>
      <SidebarRail />
    </Sidebar>
  )
}
