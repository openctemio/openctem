'use client'

import { useEffect, useMemo, useState } from 'react'
import { usePathname } from 'next/navigation'
import { ArrowLeft, Search } from 'lucide-react'
import {
  SidebarInput,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebarActions,
} from '@/components/ui/sidebar'
import { useTranslation } from '@/context/i18n-provider'
import { useSettingsNav } from '@/hooks/use-settings-nav'
import { activeSettingsItem, isSettingsShellPath } from '@/config/settings-nav'
import { searchSettings } from '@/config/settings-search'
import { GroupedNav, type GroupedNavSection } from './grouped-nav'
import { NAV_BUTTON_CLASS } from './nav-group'
import { NavPendingHint, SidebarLink } from './sidebar-link'

const RETURN_KEY = 'openctem:settings-return-to'

/**
 * Remember the last app page (outside the settings shell), so "Back to app"
 * returns there instead of always to the dashboard. Per tab, best effort:
 * storage can be unavailable, and then the link goes to "/".
 */
export function useRememberAppPath() {
  const pathname = usePathname()
  useEffect(() => {
    if (isSettingsShellPath(pathname)) return
    try {
      sessionStorage.setItem(RETURN_KEY, pathname + window.location.search)
    } catch {
      // Storage blocked (private mode, sandbox): fall back to "/".
    }
  }, [pathname])
}

function readReturnPath(): string {
  try {
    const p = sessionStorage.getItem(RETURN_KEY)
    // Only same-app absolute paths; never a protocol-relative or external URL.
    if (p && p.startsWith('/') && !p.startsWith('//')) return p
  } catch {
    // ignore
  }
  return '/'
}

/**
 * The settings rail: rendered in the left sidebar on every settings route
 * (see isSettingsShellPath), in place of the CTEM navigation.
 *
 * "Back to app", a search box that finds pages and the settings inside them
 * (src/config/settings-search.ts), then the groups from
 * src/config/settings-nav.ts, hidden per permission and module.
 */
export function SettingsSidebarNav() {
  const pathname = usePathname()
  const { t } = useTranslation()
  const groups = useSettingsNav()
  const [query, setQuery] = useState('')
  const [backHref, setBackHref] = useState('/')
  const { setOpenMobile } = useSidebarActions()

  // Read after mount: sessionStorage does not exist during server rendering.
  useEffect(() => {
    setBackHref(readReturnPath())
  }, [])

  const activeUrl = useMemo(
    () =>
      activeSettingsItem(
        pathname,
        groups.flatMap((g) => g.items)
      )?.url,
    [pathname, groups]
  )

  // No query: the groups. A query: the matching pages and the matching
  // settings inside them ("Authentication › IP allowlist"), per group.
  const sections: GroupedNavSection[] = useMemo(
    () =>
      groups.map((group) => ({
        key: group.id,
        label: group.label,
        items: query.trim()
          ? searchSettings(group.items, query).map((r) => ({
              key: r.key,
              // A setting row shows the setting; it follows its page's row
              // when the page matches too, and keeps the page's icon.
              title: r.label,
              url: r.href,
              icon: r.icon,
            }))
          : group.items.map((item) => ({
              key: item.id,
              title: item.label,
              url: item.url,
              icon: item.icon,
              badge: item.badge ? t('settings.badge.soon', 'Soon') : undefined,
            })),
      })),
    [groups, query, t]
  )
  const noMatch = query.trim() !== '' && sections.every((s) => s.items.length === 0)
  const backLabel = t('settings.backToApp', 'Back to app')
  const filterLabel = t('settings.filter', 'Search settings')

  return (
    <nav aria-label={t('nav.item.settings', 'Settings')} className="flex flex-col gap-1">
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
      {/* The filter needs room to type; on the icon rail it is hidden. */}
      <div className="relative mt-1 group-data-[collapsible=icon]:hidden">
        {/* The icon sits on the nav icons' axis and the text starts where the
            item labels start, so the filter lines up with the rows below. */}
        <Search
          aria-hidden
          className="pointer-events-none absolute start-2 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
        />
        <SidebarInput
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape' && query) {
              e.stopPropagation()
              setQuery('')
            }
          }}
          placeholder={`${filterLabel}…`}
          aria-label={filterLabel}
          className="ps-[34px] text-sm in-data-[mobile=true]:h-11 in-data-[mobile=true]:text-base"
        />
      </div>
      <GroupedNav sections={sections} activeUrl={activeUrl} />
      {noMatch && (
        <p
          role="status"
          className="px-1.5 py-2 text-sm text-muted-foreground group-data-[collapsible=icon]:hidden"
        >
          {t('settings.noMatch', 'No settings match your filter.')}
        </p>
      )}
    </nav>
  )
}
