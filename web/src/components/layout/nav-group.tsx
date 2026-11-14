'use client'

import { type ReactNode, type ElementType, useId, useMemo, useState, memo } from 'react'
import { usePathname } from 'next/navigation'
import { ChevronRight } from 'lucide-react'
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  useSidebar,
  useSidebarActions,
} from '@/components/ui/sidebar'
import { Badge } from '@/components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuPortal,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  type NavCollapsible,
  type NavItem,
  type NavLink,
  type NavGroup as NavGroupProps,
} from '@/components/types'
import { useDynamicBadges, getBadgeValue, type DynamicBadges } from '@/hooks/use-dynamic-badges'
import {
  useTenantModules,
  type LicensingModule,
} from '@/features/integrations/api/use-tenant-modules'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import { NavCount } from './nav-count'
import {
  NAV_BUTTON_CLASS,
  NAV_SECTION_HEADER_CLASS,
  SUB_BUTTON_CLASS,
  SUB_LABEL_CLASS,
  SUB_MENU_CLASS,
} from './nav-classes'

// Shared row classes live in nav-classes.ts (the quick views use them too,
// and they import nothing from here); re-exported for existing callers.
export { MOBILE_ROW_CLASS, NAV_BUTTON_CLASS, NAV_COLUMN_CLASS } from './nav-classes'
import { PinAction } from '@/features/nav-pins/components/pin-action'
import { subModuleStatus } from '@/lib/permissions/sub-modules'
import { activeSubItemUrl, checkIsActive, sectionHasActiveRoute } from './nav-active'
import { NavPendingHint, SidebarLink } from './sidebar-link'
import { FindingsQuickViews } from './findings-quick-views'
import { AssetsQuickViews } from './assets-quick-views'

/** Maps a sidebar group title to its i18n key, e.g. "Scoping" → "nav.group.scoping". */
function groupTitleKey(title: string): string {
  return `nav.group.${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
}

/** Maps a sidebar item title to its i18n key, e.g. "Attack Surface" → "nav.item.attack-surface". */
function navItemKey(title: string): string {
  return `nav.item.${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`
}

/**
 * Translated sidebar item label. Centralises the t() call so the many memoized
 * menu sub-components can render a localized label with the English title as the
 * fallback (untranslated items degrade gracefully).
 */
function NavLabel({ title }: { title: string }) {
  const { t } = useTranslation()
  return <>{t(navItemKey(title), title)}</>
}

/**
 * Height-animated disclosure (grid-rows 0fr↔1fr). The content stays mounted so
 * the same element animates both an accordion toggle and the rail collapse,
 * instead of popping in or out; it is `inert` while closed.
 */
function AnimatedCollapse({
  open,
  id,
  children,
}: {
  open: boolean
  id?: string
  children: ReactNode
}) {
  return (
    <div
      id={id}
      inert={!open}
      className={cn(
        // The same duration and curve as the sidebar's own width animation
        // (ease-sidebar), so a rail collapse reads as one motion rather than two.
        'grid transition-[grid-template-rows,opacity] duration-250 ease-sidebar motion-reduce:transition-none',
        open ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
      )}
    >
      <div className="min-h-0 overflow-hidden">{children}</div>
    </div>
  )
}

/**
 * A section label between clusters of nav rows ("Pinned", "CTEM cycle"):
 * 12/16 500 dim, 16px above and 4px below. On the icon rail it folds to
 * nothing, so the icons stand in one even column.
 */
export function NavClusterLabel({ label }: { label: string }) {
  return (
    <div
      data-slot="nav-cluster-label"
      className="flex h-9 shrink-0 items-end overflow-hidden px-2 pb-1 transition-[height,opacity] duration-250 ease-sidebar motion-reduce:transition-none group-data-[collapsible=icon]:h-0 group-data-[collapsible=icon]:pb-0 group-data-[collapsible=icon]:opacity-0"
    >
      <span className="truncate text-cap-m text-fg-dim">{label}</span>
    </div>
  )
}

/**
 * NavGroup — one CTEM section in the sidebar.
 *
 * Every titled section renders as a collapsible header row (icon + label +
 * rotating chevron) following shadcn's `sidebar-07` pattern, with its items
 * nested underneath a rail. The ungrouped section (empty title, e.g. Dashboard)
 * renders its items as plain top-level links.
 *
 * app-sidebar hosts a single <SidebarGroup><SidebarMenu> and maps every group
 * through here, so the rows share one compact `gap-1` rhythm (no per-section
 * padding / labels that would open big vertical gaps).
 */
function NavGroupComponent({ title, icon, url, items }: NavGroupProps) {
  const dynamicBadges = useDynamicBadges()
  const pathname = usePathname()

  // Ungrouped rows (Dashboard) — plain top-level links, no group heading.
  if (!title) {
    // One row lights up: the deepest match (Approvals at /findings/approvals,
    // not Findings as well).
    const activeUrl = activeSubItemUrl(
      pathname,
      items.filter((i): i is NavLink => !('items' in i))
    )
    return (
      <SidebarMenu>
        {items.map((item) =>
          'items' in item ? null : (
            <SidebarMenuLink
              key={`${item.title}-${String(item.url)}`}
              item={item}
              dynamicBadges={dynamicBadges}
              active={item.url === activeUrl}
            />
          )
        )}
      </SidebarMenu>
    )
  }

  // Every titled CTEM section renders as a collapsible header (icon + label +
  // chevron) that auto-opens when it owns the active route and stays collapsed
  // otherwise — so the sidebar shows the product's shape at the top level and
  // only the relevant section's items expand, instead of one long always-open
  // list. In the collapsed icon-rail NavSection flips to a dropdown flyout so
  // the whole tree is still reachable from the icon.
  return (
    <SidebarMenu>
      <NavSection title={title} icon={icon} url={url} items={items} dynamicBadges={dynamicBadges} />
    </SidebarMenu>
  )
}

export function NavBadge({
  children,
  variant,
}: {
  children: ReactNode
  variant?: 'default' | 'soon' | 'beta'
}) {
  // Special styling for "Soon" badge to indicate Coming Soon pages
  if (variant === 'soon' || children === 'Soon') {
    return (
      <Badge
        variant="outline"
        className="ms-auto shrink-0 rounded-full px-1.5 py-0 text-[10px] text-muted-foreground border-dashed"
      >
        {children}
      </Badge>
    )
  }
  // Beta badge styling
  if (variant === 'beta' || children === 'Beta') {
    return (
      <Badge variant="secondary" className="ms-auto shrink-0 rounded-full px-1.5 py-0 text-[10px]">
        {children}
      </Badge>
    )
  }
  return <NavCount tone="action">{children}</NavCount>
}

/**
 * Get the appropriate badge based on releaseStatus
 */
function getReleaseStatusBadge(
  releaseStatus?: string
): { text: string; variant: 'soon' | 'beta' } | null {
  if (releaseStatus === 'coming_soon') {
    return { text: 'Soon', variant: 'soon' }
  }
  if (releaseStatus === 'beta') {
    return { text: 'Beta', variant: 'beta' }
  }
  return null
}

/**
 * Filter sub-items based on sub-modules from API.
 * - Items without subModuleKey are always shown (like "Overview")
 * - Items with subModuleKey are filtered by sub-module presence in API response
 * - API only returns active modules, so if not in response = hidden
 * - "disabled" release status hides completely
 * - "coming_soon" and "beta" modules get their release status applied
 */
function useFilteredSubItems(
  items: NavLink[],
  parentModuleId: string | undefined,
  subModules: Record<string, LicensingModule[]>
) {
  return useMemo(
    () =>
      items.flatMap((item) => {
        const status = subModuleStatus(parentModuleId, item.subModuleKey, subModules)
        if (status === false) return []
        return [status === undefined ? item : { ...item, releaseStatus: status }]
      }),
    [items, parentModuleId, subModules]
  )
}

/**
 * SidebarMenuLink - top-level plain link (Dashboard). Memoized so it only
 * re-renders when the pathname changes.
 */
const SidebarMenuLink = memo(function SidebarMenuLink({
  item,
  dynamicBadges,
  active,
}: {
  item: NavLink
  dynamicBadges: DynamicBadges
  /** Set by a parent that picks one active row among siblings. */
  active?: boolean
}) {
  const pathname = usePathname()
  const { setOpenMobile } = useSidebarActions()
  const { t } = useTranslation()
  // The rail tooltip names the row in the reader's language.
  const title = t(navItemKey(item.title), item.title)
  const badge = getBadgeValue(dynamicBadges, item.url as string, item.badge)
  const releaseStatusBadge = getReleaseStatusBadge(item.releaseStatus)
  const isComingSoon = item.releaseStatus === 'coming_soon'

  // If coming soon, render as disabled span instead of link
  if (isComingSoon) {
    return (
      <SidebarMenuItem>
        <SidebarMenuButton
          tooltip={t('nav.comingSoonTooltip', '{title} (coming soon)', { title })}
          className={cn(NAV_BUTTON_CLASS, 'cursor-not-allowed opacity-60')}
        >
          {item.icon && <item.icon />}
          <span>
            <NavLabel title={item.title} />
          </span>
          {releaseStatusBadge && (
            <NavBadge variant={releaseStatusBadge.variant}>{releaseStatusBadge.text}</NavBadge>
          )}
        </SidebarMenuButton>
      </SidebarMenuItem>
    )
  }

  const isActive = active ?? checkIsActive(pathname, item)
  return (
    <SidebarMenuItem>
      <SidebarMenuButton asChild isActive={isActive} tooltip={title} className={NAV_BUTTON_CLASS}>
        <SidebarLink
          href={item.url}
          // A list with quick views hands "current page" to its active view
          // (one current row per sidebar, as the fill).
          aria-current={isActive && !item.quickViews ? 'page' : undefined}
          onClick={() => setOpenMobile(false)}
        >
          {item.icon && <item.icon />}
          <span>
            <NavLabel title={item.title} />
            <NavPendingHint />
          </span>
          {releaseStatusBadge ? (
            <NavBadge variant={releaseStatusBadge.variant}>{releaseStatusBadge.text}</NavBadge>
          ) : (
            badge && <NavBadge>{badge}</NavBadge>
          )}
        </SidebarLink>
      </SidebarMenuButton>
      {typeof item.url === 'string' && (
        <PinAction pin={{ kind: 'page', ref: item.url }} label={item.title} />
      )}
      {item.quickViews === 'findings' && <FindingsQuickViews />}
    </SidebarMenuItem>
  )
})

SidebarMenuLink.displayName = 'SidebarMenuLink'

/**
 * NavSection - a top-level CTEM section rendered as a collapsible header
 * (icon + label + chevron), sidebar-07 style. Auto-expands when it owns the
 * active route; collapses otherwise. In the collapsed icon-rail it flips to a
 * dropdown flyout so the whole tree stays reachable from the icon.
 */
const NavSection = memo(function NavSection({
  title,
  icon: SectionIcon,
  url,
  items,
  dynamicBadges,
}: {
  title: string
  icon?: ElementType
  /** The section overview: the rail flyout's heading links to it (see NavGroup.url). */
  url?: string
  items: NavItem[]
  dynamicBadges: DynamicBadges
}) {
  const { state, isMobile } = useSidebar()
  const rail = state === 'collapsed' && !isMobile
  const pathname = usePathname()
  const { t } = useTranslation()
  const contentId = useId()
  const label = t(groupTitleKey(title), title)

  const sectionActive = useMemo(() => sectionHasActiveRoute(pathname, items), [pathname, items])
  const activeLeafUrl = useMemo(
    () =>
      activeSubItemUrl(
        pathname,
        items.filter((i): i is NavLink => !('items' in i))
      ),
    [pathname, items]
  )

  // Open by default when the section owns the current page, and re-open when the
  // user navigates into it; leaving a section never forces it shut.
  const [open, setOpen] = useState(sectionActive)
  const [prevActive, setPrevActive] = useState(sectionActive)
  if (sectionActive !== prevActive) {
    setPrevActive(sectionActive)
    if (sectionActive) setOpen(true)
  }

  return (
    <SidebarMenuItem>
      {rail ? (
        <NavSectionRailMenu
          label={label}
          icon={SectionIcon}
          url={url}
          items={items}
          sectionActive={sectionActive}
          dynamicBadges={dynamicBadges}
        />
      ) : (
        // Every section header only folds and unfolds; it never navigates, even
        // when the section has an overview (`url`). The overview is the
        // section's own "Overview" row, one click away.
        <SidebarMenuButton
          tooltip={label}
          aria-expanded={open}
          aria-controls={contentId}
          data-current={sectionActive}
          onClick={() => setOpen((o) => !o)}
          className={NAV_SECTION_HEADER_CLASS}
        >
          {SectionIcon && <SectionIcon />}
          <span>{label}</span>
          <ChevronRight
            className={cn(
              'ms-auto size-3.5! transition-transform duration-200 motion-reduce:transition-none rtl:rotate-180',
              open && 'rotate-90 rtl:rotate-90'
            )}
          />
        </SidebarMenuButton>
      )}
      {/* Same element in both states, so collapsing the rail animates the open
          section shut instead of dropping it (and jumping the rows below). */}
      <AnimatedCollapse id={contentId} open={open && !rail}>
        <SidebarMenuSub className={SUB_MENU_CLASS}>
          {items.map((item) =>
            'items' in item ? (
              <NavSubCollapsible key={item.title} item={item} dynamicBadges={dynamicBadges} />
            ) : (
              <NavSubLeaf
                key={`${item.title}-${String(item.url)}`}
                item={item}
                dynamicBadges={dynamicBadges}
                active={item.url === activeLeafUrl}
              />
            )
          )}
        </SidebarMenuSub>
      </AnimatedCollapse>
    </SidebarMenuItem>
  )
})

NavSection.displayName = 'NavSection'

/**
 * NavSubLeaf - a leaf link inside a section's sub-menu. Shared by both a
 * section's direct children and a nested subsection's children.
 */
const NavSubLeaf = memo(function NavSubLeaf({
  item,
  dynamicBadges,
  nested = false,
  active,
}: {
  item: NavLink
  dynamicBadges: DynamicBadges
  /**
   * Third level (inside a subsection). These rows are text-only: their icons
   * mostly repeat the parent's, and dropping them gives the label back ~24px.
   */
  nested?: boolean
  /**
   * Whether this row is the current page. Siblings are resolved together by the
   * parent (longest matching url wins), so "Assets" at `/assets` does
   * not light up alongside "Activity" at `/assets/changes`.
   */
  active?: boolean
}) {
  const pathname = usePathname()
  const { setOpenMobile } = useSidebarActions()
  const badge = getBadgeValue(dynamicBadges, item.url as string, item.badge)
  const releaseStatusBadge = getReleaseStatusBadge(item.releaseStatus)
  const isComingSoon = item.releaseStatus === 'coming_soon'

  if (isComingSoon) {
    return (
      <SidebarMenuSubItem>
        <SidebarMenuSubButton className={cn(SUB_BUTTON_CLASS, 'cursor-not-allowed opacity-60')}>
          {!nested && item.icon && <item.icon className="shrink-0" />}
          <span className={SUB_LABEL_CLASS}>
            <NavLabel title={item.title} />
          </span>
          {releaseStatusBadge && (
            <NavBadge variant={releaseStatusBadge.variant}>{releaseStatusBadge.text}</NavBadge>
          )}
        </SidebarMenuSubButton>
      </SidebarMenuSubItem>
    )
  }

  const isActive = active ?? checkIsActive(pathname, item)
  return (
    <SidebarMenuSubItem>
      <SidebarMenuSubButton asChild isActive={isActive} className={SUB_BUTTON_CLASS}>
        <SidebarLink
          href={item.url}
          aria-current={isActive ? 'page' : undefined}
          onClick={() => setOpenMobile(false)}
        >
          {!nested && item.icon && <item.icon className="shrink-0" />}
          <span className={SUB_LABEL_CLASS}>
            <NavLabel title={item.title} />
            <NavPendingHint />
          </span>
          {releaseStatusBadge ? (
            <NavBadge variant={releaseStatusBadge.variant}>{releaseStatusBadge.text}</NavBadge>
          ) : (
            badge && <NavBadge>{badge}</NavBadge>
          )}
        </SidebarLink>
      </SidebarMenuSubButton>
      {item.quickViews === 'assets' && <AssetsQuickViews />}
    </SidebarMenuSubItem>
  )
})

NavSubLeaf.displayName = 'NavSubLeaf'

/**
 * NavSubCollapsible - a nested subsection inside a section (e.g. Penetration
 * Testing under Validation, or Scanning/Organization/Integrations under
 * Settings). Renders as a second-level collapsible on its own rail so a large
 * settings tree stays organised without flattening into a 20-row wall.
 */
const NavSubCollapsible = memo(function NavSubCollapsible({
  item,
  dynamicBadges,
}: {
  item: NavCollapsible
  dynamicBadges: DynamicBadges
}) {
  const pathname = usePathname()
  const { subModules } = useTenantModules()
  const releaseStatusBadge = getReleaseStatusBadge(item.releaseStatus)
  const contentId = useId()

  const filteredItems = useFilteredSubItems(item.items, item.module, subModules)
  const activeSubUrl = useMemo(
    () => activeSubItemUrl(pathname, filteredItems),
    [pathname, filteredItems]
  )
  const hasActive = activeSubUrl !== undefined

  const [open, setOpen] = useState(hasActive)
  const [prevActive, setPrevActive] = useState(hasActive)
  if (hasActive !== prevActive) {
    setPrevActive(hasActive)
    if (hasActive) setOpen(true)
  }

  return (
    <SidebarMenuSubItem>
      <SidebarMenuSubButton asChild className={cn(SUB_BUTTON_CLASS, 'cursor-pointer')}>
        <button
          type="button"
          aria-expanded={open}
          aria-controls={contentId}
          data-active={hasActive && !open}
          onClick={() => setOpen((o) => !o)}
        >
          {item.icon && <item.icon className="shrink-0" />}
          <span className={SUB_LABEL_CLASS}>
            <NavLabel title={item.title} />
          </span>
          {releaseStatusBadge && (
            <NavBadge variant={releaseStatusBadge.variant}>{releaseStatusBadge.text}</NavBadge>
          )}
          <ChevronRight
            className={cn(
              'ms-auto size-3.5 shrink-0 text-muted-foreground transition-transform duration-200 motion-reduce:transition-none rtl:rotate-180',
              open && 'rotate-90 rtl:rotate-90'
            )}
          />
        </button>
      </SidebarMenuSubButton>
      <AnimatedCollapse id={contentId} open={open}>
        <SidebarMenuSub className={SUB_MENU_CLASS}>
          {filteredItems.map((sub) => (
            <NavSubLeaf
              key={sub.title}
              item={sub}
              dynamicBadges={dynamicBadges}
              nested
              active={sub.url === activeSubUrl}
            />
          ))}
        </SidebarMenuSub>
      </AnimatedCollapse>
    </SidebarMenuSubItem>
  )
})

NavSubCollapsible.displayName = 'NavSubCollapsible'

/**
 * NavSectionRailMenu - the icon-rail representation of a section.
 * The section header becomes an icon button; its whole tree lives in a
 * dropdown (nested subsections become dropdown sub-menus) so nothing is lost
 * when the sidebar is collapsed.
 */
const NavSectionRailMenu = memo(function NavSectionRailMenu({
  label,
  icon: SectionIcon,
  url,
  items,
  sectionActive,
  dynamicBadges,
}: {
  label: string
  icon?: ElementType
  url?: string
  items: NavItem[]
  sectionActive: boolean
  dynamicBadges: DynamicBadges
}) {
  const pathname = usePathname()
  const activeLeafUrl = activeSubItemUrl(
    pathname,
    items.filter((i): i is NavLink => !('items' in i))
  )

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <SidebarMenuButton
          tooltip={label}
          aria-label={label}
          isActive={sectionActive}
          className={NAV_BUTTON_CLASS}
        >
          {SectionIcon && <SectionIcon />}
        </SidebarMenuButton>
      </DropdownMenuTrigger>
      {/* 200 wide, 8 px right of the rail button; a long label wraps. */}
      <DropdownMenuContent side="right" align="start" sideOffset={8} className="w-50">
        {url ? (
          // The flyout's heading opens the section overview (a menu item, so
          // navigating is expected here; the expanded header only toggles).
          <DropdownMenuItem asChild className="text-cap-m text-fg-dim">
            <SidebarLink href={url}>{label}</SidebarLink>
          </DropdownMenuItem>
        ) : (
          <DropdownMenuLabel className="text-cap-m text-fg-dim">{label}</DropdownMenuLabel>
        )}
        <DropdownMenuSeparator />
        {items.map((item) =>
          'items' in item ? (
            <CollapsedDropdownSubsection
              key={item.title}
              item={item}
              pathname={pathname}
              dynamicBadges={dynamicBadges}
            />
          ) : (
            <CollapsedDropdownLeaf
              key={`${item.title}-${String(item.url)}`}
              item={item}
              dynamicBadges={dynamicBadges}
              active={item.url === activeLeafUrl}
            />
          )
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
})

NavSectionRailMenu.displayName = 'NavSectionRailMenu'

/** A section's nested subsection rendered as a dropdown sub-menu (rail mode). */
function CollapsedDropdownSubsection({
  item,
  pathname,
  dynamicBadges,
}: {
  item: NavCollapsible
  pathname: string
  dynamicBadges: DynamicBadges
}) {
  const { subModules } = useTenantModules()
  const filteredItems = useFilteredSubItems(item.items, item.module, subModules)
  const activeUrl = activeSubItemUrl(pathname, filteredItems)

  return (
    <DropdownMenuSub>
      <DropdownMenuSubTrigger>
        {item.icon && <item.icon />}
        <span className="min-w-0 text-wrap">
          <NavLabel title={item.title} />
        </span>
      </DropdownMenuSubTrigger>
      <DropdownMenuPortal>
        <DropdownMenuSubContent className="w-50">
          {filteredItems.map((sub) => (
            <CollapsedDropdownLeaf
              key={`${sub.title}-${String(sub.url)}`}
              item={sub}
              dynamicBadges={dynamicBadges}
              active={sub.url === activeUrl}
            />
          ))}
        </DropdownMenuSubContent>
      </DropdownMenuPortal>
    </DropdownMenuSub>
  )
}

/** A leaf link rendered as a dropdown item (rail mode). */
function CollapsedDropdownLeaf({
  item,
  dynamicBadges,
  active,
}: {
  item: NavLink
  dynamicBadges: DynamicBadges
  active: boolean
}) {
  const badge = getBadgeValue(dynamicBadges, item.url as string, item.badge)
  const releaseStatusBadge = getReleaseStatusBadge(item.releaseStatus)
  const isComingSoon = item.releaseStatus === 'coming_soon'

  if (isComingSoon) {
    return (
      <DropdownMenuItem disabled className="cursor-not-allowed opacity-60">
        {item.icon && <item.icon />}
        <span className="min-w-0 text-wrap">
          <NavLabel title={item.title} />
        </span>
        {releaseStatusBadge && <NavCount>{releaseStatusBadge.text}</NavCount>}
      </DropdownMenuItem>
    )
  }

  return (
    <DropdownMenuItem asChild>
      <SidebarLink
        href={item.url}
        aria-current={active ? 'page' : undefined}
        className={cn(active && 'bg-sidebar-accent font-medium')}
      >
        {item.icon && <item.icon />}
        <span className="min-w-0 text-wrap">
          <NavLabel title={item.title} />
          <NavPendingHint />
        </span>
        {releaseStatusBadge ? (
          <NavCount>{releaseStatusBadge.text}</NavCount>
        ) : (
          badge && <NavCount>{badge}</NavCount>
        )}
      </SidebarLink>
    </DropdownMenuItem>
  )
}

/**
 * Memoized NavGroup to prevent re-renders when pathname changes
 * Only re-renders when items or title props actually change
 */
export const NavGroup = memo(NavGroupComponent, (prevProps, nextProps) => {
  // Only re-render if title or items array reference changes
  // This prevents re-render when only pathname changes (which is handled internally)
  return (
    prevProps.title === nextProps.title &&
    prevProps.url === nextProps.url &&
    prevProps.items === nextProps.items &&
    prevProps.icon === nextProps.icon
  )
})

NavGroup.displayName = 'NavGroup'
