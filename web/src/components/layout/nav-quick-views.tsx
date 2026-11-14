'use client'

import {
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  useSidebarActions,
} from '@/components/ui/sidebar'
import { safeHref } from '@/lib/safe-href'
import { NavCount } from './nav-count'
import { SUB_BUTTON_CLASS, SUB_LABEL_CLASS } from './nav-classes'
import { SidebarLink } from './sidebar-link'
import type { NavPin } from '@/features/nav-pins/api/use-nav-pins'
import { PinAction } from '@/features/nav-pins/components/pin-action'

/** One built-in view of a list, as the sidebar lists it under the list's row. */
export interface NavQuickView {
  key: string
  /** Already translated. */
  label: string
  /** The list URL with the list's own params. */
  href: string
  count: number
  active: boolean
  /** The count is a problem to act on (shown in the error colour when above zero). */
  danger?: boolean
  /** The view can be pinned to the top of the sidebar as this pin. */
  pin?: Pick<NavPin, 'kind' | 'ref'>
}

/**
 * The quick views under a list's sidebar row (Findings, Assets): each is a
 * plain link to the list with its own params, with a count. A zero count shows
 * nothing. The list that owns the views decides when they show (only while the
 * list is open) and fetches their counts.
 */
export function NavQuickViewList({
  label,
  views,
  fallbackHref,
  className,
}: {
  /** Accessible name of the list, e.g. "Findings views". */
  label: string
  views: NavQuickView[]
  /** Where a link goes if its href is refused by safeHref. */
  fallbackHref: string
  className?: string
}) {
  const { setOpenMobile } = useSidebarActions()
  if (views.length === 0) return null
  return (
    <SidebarMenuSub aria-label={label} className={className}>
      {views.map((v) => (
        <SidebarMenuSubItem key={v.key}>
          <SidebarMenuSubButton asChild isActive={v.active} className={SUB_BUTTON_CLASS}>
            <SidebarLink
              href={safeHref(v.href) ?? safeHref(fallbackHref) ?? '/'}
              aria-current={v.active ? 'page' : undefined}
              onClick={() => setOpenMobile(false)}
            >
              <span className={SUB_LABEL_CLASS}>{v.label}</span>
              {v.count > 0 && (
                <NavCount tone={v.danger ? 'danger' : 'muted'}>{v.count.toLocaleString()}</NavCount>
              )}
            </SidebarLink>
          </SidebarMenuSubButton>
          {v.pin && <PinAction pin={v.pin} label={v.label} sub />}
        </SidebarMenuSubItem>
      ))}
    </SidebarMenuSub>
  )
}
