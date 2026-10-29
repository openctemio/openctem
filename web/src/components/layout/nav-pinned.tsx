'use client'

import { usePathname } from 'next/navigation'
import { Eye, Pin } from 'lucide-react'
import {
  SidebarGroup,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebarActions,
} from '@/components/ui/sidebar'
import { useTranslation } from '@/context/i18n-provider'
import { useUrlParams } from '@/hooks/use-url-param'
import { safeHref } from '@/lib/safe-href'
import {
  QUICK_VIEW_LABELS,
  quickViewHref,
  quickViewLabelKey,
  type QuickViewKey,
} from '@/features/findings/lib/quick-views'
import { useNavPins, type NavPin } from '@/features/nav-pins/api/use-nav-pins'
import { PinAction } from '@/features/nav-pins/components/pin-action'
import type { NavGroup, NavItem } from '../types'
import { NavClusterLabel } from './nav-group'
import { NavCount } from './nav-count'
import { SidebarLink } from './sidebar-link'

/** Every page the sidebar links to, by path, with its title and icon. */
export function pagesOf(
  groups: NavGroup[]
): Map<string, { title: string; icon?: React.ElementType }> {
  const out = new Map<string, { title: string; icon?: React.ElementType }>()
  const add = (items: NavItem[]) => {
    for (const i of items) {
      if ('url' in i && typeof i.url === 'string') out.set(i.url, { title: i.title, icon: i.icon })
      if ('items' in i && i.items) add(i.items as NavItem[])
    }
  }
  for (const g of groups) add(g.items)
  return out
}

export interface PinnedRow {
  pin: NavPin
  label: string
  href: string
  icon: React.ElementType
  count?: number
}

/**
 * The rows the Pinned section shows (pure): a page the sidebar does not offer
 * this person (a permission or module they lack) is left out, as is a link
 * safeHref refuses.
 */
export function pinnedRows(
  pins: NavPin[],
  pages: Map<string, { title: string; icon?: React.ElementType }>,
  includeInformational: boolean,
  quickViewLabel: (key: string) => string
): PinnedRow[] {
  const rows: PinnedRow[] = []
  for (const p of pins) {
    if (p.kind === 'page') {
      const page = pages.get(p.ref)
      const href = safeHref(p.ref)
      if (!page || !href) continue
      rows.push({ pin: p, label: page.title, href, icon: page.icon ?? Pin })
    } else if (p.kind === 'quick_view' && p.params) {
      const href = safeHref(quickViewHref(p.params, includeInformational))
      if (!href) continue
      rows.push({ pin: p, label: quickViewLabel(p.ref), href, icon: Eye, count: p.count })
    } else if (p.kind === 'saved_view' && p.name) {
      const href = safeHref(`/findings?view=${encodeURIComponent(p.ref)}`)
      if (!href) continue
      rows.push({ pin: p, label: p.name, href, icon: Eye, count: p.count })
    }
  }
  return rows
}

/**
 * Pinned: the pages and findings views this person pinned, at the top of the
 * sidebar, each with its live count (computed by the API as this person).
 * Nothing shows until something is pinned.
 */
export function NavPinned({ groups }: { groups: NavGroup[] }) {
  const { t } = useTranslation()
  const pathname = usePathname()
  const search = useUrlParams()
  const { setOpenMobile } = useSidebarActions()
  const { pins, includeInformational } = useNavPins()
  const rows = pinnedRows(pins, pagesOf(groups), includeInformational, (k) =>
    t(quickViewLabelKey(k), QUICK_VIEW_LABELS[k as QuickViewKey] ?? k)
  )
  if (rows.length === 0) return null
  const here = `${pathname}${search.toString() ? `?${search.toString()}` : ''}`
  return (
    <>
      <NavClusterLabel label={t('nav.pins.title', 'Pinned')} />
      <SidebarGroup className="p-0" aria-label={t('nav.pins.title', 'Pinned')}>
        <SidebarMenu>
          {rows.map((r) => {
            const active = r.pin.kind === 'page' ? pathname === r.href : here === r.href
            // A pinned page or quick view is also a row of the tree below, which
            // holds the one fill; the pin mirrors it unfilled. A saved view has
            // no row of its own, so its pin is the current row.
            const filled = active && r.pin.kind === 'saved_view'
            return (
              <SidebarMenuItem key={`${r.pin.kind}:${r.pin.ref}`} data-slot="nav-pinned-item">
                <SidebarMenuButton
                  asChild
                  isActive={filled}
                  data-current={active && !filled ? true : undefined}
                  tooltip={r.label}
                >
                  <SidebarLink
                    href={r.href}
                    aria-current={active ? 'page' : undefined}
                    onClick={() => setOpenMobile(false)}
                  >
                    <r.icon aria-hidden />
                    <span dir="auto" className="truncate [unicode-bidi:isolate]">
                      {r.label}
                    </span>
                    {typeof r.count === 'number' && r.count > 0 && (
                      <NavCount>{r.count.toLocaleString()}</NavCount>
                    )}
                  </SidebarLink>
                </SidebarMenuButton>
                <PinAction pin={r.pin} label={r.label} />
              </SidebarMenuItem>
            )
          })}
        </SidebarMenu>
      </SidebarGroup>
      <NavClusterLabel />
    </>
  )
}
