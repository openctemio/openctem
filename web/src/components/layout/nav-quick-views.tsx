'use client'

import {
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  useSidebarActions,
} from '@/components/ui/sidebar'
import { cn } from '@/lib/utils'
import { safeHref } from '@/lib/safe-href'
import { NavCount } from './nav-count'
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
    <SidebarMenuSub
      aria-label={label}
      className={cn('ms-[15px] me-0 gap-0.5 py-1 pe-0 translate-x-0', className)}
    >
      {views.map((v) => (
        <SidebarMenuSubItem key={v.key}>
          <SidebarMenuSubButton
            asChild
            isActive={v.active}
            className="relative h-auto min-h-7 w-full py-1 text-[13px] text-sidebar-foreground/80 data-[active=true]:font-medium in-data-[mobile=true]:min-h-11 in-data-[mobile=true]:text-base"
          >
            <SidebarLink
              href={safeHref(v.href) ?? safeHref(fallbackHref) ?? '/'}
              aria-current={v.active ? 'page' : undefined}
              onClick={() => setOpenMobile(false)}
            >
              <span className="flex-1 whitespace-normal! text-start leading-snug text-pretty">
                {v.label}
              </span>
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
