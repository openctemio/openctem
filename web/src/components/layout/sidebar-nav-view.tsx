'use client'

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ComponentProps,
  type ReactNode,
} from 'react'
import { usePathname } from 'next/navigation'
import { SidebarMenuButton, useSidebar, useSidebarActions } from '@/components/ui/sidebar'
import { isSettingsShellPath } from '@/config/settings-nav'
import { NAV_BUTTON_CLASS } from './nav-group'
import { NavPendingHint, SidebarLink } from './sidebar-link'

/** The navigation sets the app sidebar can show. */
export type SidebarNavView = 'app' | 'settings'

/** The set that belongs to a route: the settings rail on settings routes. */
export function routeNavView(pathname: string): SidebarNavView {
  return isSettingsShellPath(pathname) ? 'settings' : 'app'
}

interface NavViewContextValue {
  /** The set the sidebar shows now. */
  view: SidebarNavView
  /**
   * Show another set in the phone drawer without leaving the page. Returns
   * false when there is nothing to switch (desktop, or that set is already
   * shown); the control is then an ordinary page link.
   */
  showView: (view: SidebarNavView) => boolean
  /** Bumped on each in-place switch, so the new set can take the focus. */
  switchCount: number
}

const NavViewContext = createContext<NavViewContextValue | null>(null)

/**
 * Which navigation set the sidebar shows, and the one rule for the controls
 * that move between sets ("Settings", "Back to app").
 *
 * The set follows the route: the settings rail on settings routes, the app
 * navigation elsewhere. On a phone the sidebar is a drawer over the page, and
 * moving between sets there is browsing, not a destination: the drawer stays
 * open and shows the other set in place, and only picking a page navigates
 * (and closes the drawer). The switch is scoped to the page it was made on, so
 * a navigation (a picked row, the browser's back) hands the choice back to the
 * route, and each time the drawer opens it starts on the set of the page
 * underneath. On desktop the sidebar sits next to the page and the two always
 * agree: the controls are links, as before.
 */
export function SidebarNavViewProvider({ children }: { children: ReactNode }) {
  const pathname = usePathname()
  const { isMobile, openMobile } = useSidebar()
  const [override, setOverride] = useState<{ view: SidebarNavView; path: string } | null>(null)
  const [switchCount, setSwitchCount] = useState(0)

  // A drawer that opens starts on the page's own set. Reset during render
  // (not in an effect), so the drawer never paints the old set first; and not
  // on close, so the set does not change under the 0.2s slide-out.
  const [wasOpen, setWasOpen] = useState(openMobile)
  if (wasOpen !== openMobile) {
    setWasOpen(openMobile)
    if (openMobile && override) setOverride(null)
  }

  const routeView = routeNavView(pathname)
  const view = isMobile && override && override.path === pathname ? override.view : routeView

  const showView = useCallback(
    (next: SidebarNavView) => {
      if (!isMobile || next === view) return false
      setOverride(next === routeView ? null : { view: next, path: pathname })
      setSwitchCount((n) => n + 1)
      return true
    },
    [isMobile, view, routeView, pathname]
  )

  const value = useMemo(() => ({ view, showView, switchCount }), [view, showView, switchCount])
  return <NavViewContext.Provider value={value}>{children}</NavViewContext.Provider>
}

/** The sidebar's current navigation set; the route's set outside a provider. */
export function useSidebarNavView(): NavViewContextValue {
  const ctx = useContext(NavViewContext)
  const pathname = usePathname()
  return ctx ?? { view: routeNavView(pathname), showView: () => false, switchCount: 0 }
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled])'

/**
 * Renders the set the sidebar shows. After an in-place switch the first
 * control of the new set takes the focus: the control that was pressed is
 * gone, and focus would otherwise fall to the document, outside the drawer.
 */
export function SidebarNavViews({
  views,
  className,
}: {
  views: Record<SidebarNavView, ReactNode>
  className?: string
}) {
  const { view, switchCount } = useSidebarNavView()
  const ref = useRef<HTMLDivElement>(null)
  const handled = useRef(switchCount)

  useEffect(() => {
    if (handled.current === switchCount) return
    handled.current = switchCount
    ref.current?.querySelector<HTMLElement>(FOCUSABLE)?.focus()
  }, [switchCount, view])

  return (
    <div ref={ref} data-nav-view={view} className={className}>
      {views[view]}
    </div>
  )
}

type SwitchProps = Omit<ComponentProps<typeof SidebarMenuButton>, 'asChild' | 'onClick'> & {
  /** The set this control shows. */
  view: SidebarNavView
  /** The page it opens when it is a link (desktop, or the set is already shown). */
  href: string
  label: string
  icon: ReactNode
  'aria-current'?: 'page'
}

/**
 * A sidebar row that moves to another navigation set: a button that switches
 * the phone drawer in place (the drawer stays open), and a link to `href`
 * where there is nothing to switch. The one control for "Settings" and
 * "Back to app", so every such row follows the same rule.
 */
export function SidebarViewSwitch({
  view,
  href,
  label,
  icon,
  'aria-current': ariaCurrent,
  ...buttonProps
}: SwitchProps) {
  const nav = useContext(NavViewContext)
  const { isMobile } = useSidebar()
  const { setOpenMobile } = useSidebarActions()
  const switches = !!nav && isMobile && nav.view !== view

  if (switches) {
    return (
      <SidebarMenuButton
        {...buttonProps}
        tooltip={label}
        className={NAV_BUTTON_CLASS}
        onClick={() => nav.showView(view)}
      >
        {icon}
        <span>{label}</span>
      </SidebarMenuButton>
    )
  }
  return (
    <SidebarMenuButton {...buttonProps} asChild tooltip={label} className={NAV_BUTTON_CLASS}>
      <SidebarLink href={href} aria-current={ariaCurrent} onClick={() => setOpenMobile(false)}>
        {icon}
        <span>
          {label}
          <NavPendingHint />
        </span>
      </SidebarLink>
    </SidebarMenuButton>
  )
}
