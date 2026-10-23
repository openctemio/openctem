'use client'

import { usePathname } from 'next/navigation'
import {
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  useSidebarActions,
} from '@/components/ui/sidebar'
import { useTranslation } from '@/context/i18n-provider'
import { useUrlParams } from '@/hooks/use-url-param'
import { useFindingQuickViews } from '@/features/findings/api/use-quick-views'
import {
  QUICK_VIEW_LABELS,
  knownQuickViews,
  quickViewHref,
  quickViewIsActive,
  quickViewLabelKey,
  type QuickViewKey,
} from '@/features/findings/lib/quick-views'
import { cn } from '@/lib/utils'
import { safeHref } from '@/lib/safe-href'
import { SidebarLink } from './sidebar-link'

/** Whether `pathname` is a page of the Findings list (not the approvals inbox). */
export function isFindingsListPath(pathname: string): boolean {
  return pathname === '/findings'
}

/**
 * The built-in views under the Findings row, with live counts. They show on the
 * list page only, so the counts are requested (once, 60 s cache) only there;
 * every other page pays nothing. A view is a link to the list with the API's
 * own params, so the count and the list it opens always agree. A zero count
 * shows nothing; SLA breached is in the error colour when above zero.
 */
export function FindingsQuickViews() {
  const pathname = usePathname()
  const onList = isFindingsListPath(pathname)
  const { t } = useTranslation()
  const search = useUrlParams()
  const { setOpenMobile } = useSidebarActions()
  const { data } = useFindingQuickViews(onList)
  if (!onList) return null
  const views = knownQuickViews(data?.views)
  if (views.length === 0) return null

  return (
    <SidebarMenuSub
      aria-label={t('findings.quickView.nav', 'Findings views')}
      className="ms-[15px] me-0 gap-0.5 py-1 pe-0 translate-x-0"
    >
      {views.map((v) => {
        const label = t(quickViewLabelKey(v.key), QUICK_VIEW_LABELS[v.key as QuickViewKey])
        const active = quickViewIsActive(search, v)
        return (
          <SidebarMenuSubItem key={v.key}>
            <SidebarMenuSubButton
              asChild
              isActive={active}
              className="relative h-auto min-h-7 w-full py-1 text-[13px] text-sidebar-foreground/80 data-[active=true]:font-medium in-data-[mobile=true]:min-h-11 in-data-[mobile=true]:text-base"
            >
              <SidebarLink
                href={safeHref(quickViewHref(v.params)) ?? '/findings'}
                aria-current={active ? 'page' : undefined}
                onClick={() => setOpenMobile(false)}
              >
                <span className="flex-1 whitespace-normal! text-start leading-snug text-pretty">
                  {label}
                </span>
                {v.count > 0 && (
                  <span
                    className={cn(
                      'ms-auto shrink-0 text-xs tabular-nums',
                      v.key === 'sla_breached'
                        ? 'font-medium text-destructive'
                        : 'text-muted-foreground'
                    )}
                  >
                    {v.count.toLocaleString()}
                  </span>
                )}
              </SidebarLink>
            </SidebarMenuSubButton>
          </SidebarMenuSubItem>
        )
      })}
    </SidebarMenuSub>
  )
}
