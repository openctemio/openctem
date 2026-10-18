'use client'

import { usePathname } from 'next/navigation'
import { Fingerprint, LogOut, ShieldCheck } from 'lucide-react'
import Link from '@/components/link'
import {
  Sidebar,
  SidebarContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
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
import { SidebarFooterLinks } from '@/components/layout/sidebar-footer-links'
import { ADMIN_API_VERSION_PATH, setAdminApiVersionFetcher } from '@/hooks/use-build-versions'
import { adminFetch } from '@console/lib/admin-api/client'
import { useTranslation } from '@/context/i18n-provider'
import { ConsoleLanguagePicker } from './console-language-picker'
import { visibleAdminNav } from '../lib/admin-nav-visibility'
import { ADMIN_ROLE_LABELS, type AdminIdentity } from '../types'

// Help > About reads the API's build through the console's own API proxy.
setAdminApiVersionFetcher(() => adminFetch<unknown>(ADMIN_API_VERSION_PATH))

function isActive(pathname: string, url: string): boolean {
  if (url === '/') return pathname === '/'
  return pathname === url || pathname.startsWith(`${url}/`)
}

interface AdminConsoleSidebarProps {
  admin: AdminIdentity
  onSignOut: () => void
}

/**
 * Console sidebar: the shared brand row, then a fixed "Platform admin" context
 * row where the tenant shell has its organization switcher (an admin has no
 * tenant), then the console navigation and the signed-in admin.
 */
export function AdminConsoleSidebar({ admin, onSignOut }: AdminConsoleSidebarProps) {
  const pathname = usePathname()
  const { t } = useTranslation()
  // By the administrator's own role, not the session's acting one: a super
  // admin acting read-only still sees every page, and the page offers the
  // elevation next to what it unlocks.
  const sections: GroupedNavSection[] = visibleAdminNav(admin.max_role ?? admin.role).map(
    (section, i) => ({
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
    })
  )
  // The deepest entry that owns the current path is the one marked current.
  const activeUrl = sections
    .flatMap((s) => s.items.map((i) => i.url))
    .filter((url) => isActive(pathname, url))
    .sort((x, y) => y.length - x.length)[0]

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="gap-3">
        <SidebarBrand href="/" />
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              className={cn(SIDEBAR_CONTEXT_ROW_CLASS, 'pointer-events-none h-10')}
              tooltip={t('admin.shell.contextRow', 'Platform admin')}
            >
              <div className={SIDEBAR_CHIP_CLASS}>
                <ShieldCheck className="size-4" />
              </div>
              <div className="grid flex-1 text-start text-sm leading-tight">
                <span className="truncate font-semibold">
                  {t('admin.shell.contextRow', 'Platform admin')}
                </span>
                <span className="truncate text-xs text-muted-foreground">
                  {t(`admin.role.${admin.role}`, ADMIN_ROLE_LABELS[admin.role])}
                </span>
              </div>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
        <Separator orientation="horizontal" className="mt-1" />
      </SidebarHeader>

      <SidebarContent>
        <div className={NAV_COLUMN_CLASS}>
          <GroupedNav sections={sections} activeUrl={activeUrl} />
        </div>
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
