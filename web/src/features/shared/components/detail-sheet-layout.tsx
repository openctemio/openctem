/**
 * The frame of an entity detail drawer, taken from the sensor drawer (the
 * reference in docs/ui-style-contract.md §8):
 *
 *   <DetailSheet
 *     open={open}
 *     onOpenChange={setOpen}
 *     header={
 *       <DetailHeader
 *         title={sensor.name}
 *         badges={<SensorStateBadge … />}
 *         meta={['Scanner · long-running', 'zone dmz']}
 *         menu={[{ label: 'Rotate key', icon: KeyRound, onSelect: rotate }]}
 *         actions={<Button size="sm">Edit</Button>}
 *         onClose={() => setOpen(false)}
 *       />
 *     }
 *     tabs={<DetailTabs tabs={TABS} value={tab} onValueChange={setTab} />}
 *     panel={tab}
 *   >
 *     …the body: DetailCallout, DetailChecklist, DetailStatGrid, DetailSections…
 *   </DetailSheet>
 *
 * A right-hand drawer from `md`, a bottom sheet on phones. The header (title,
 * state, actions, tabs) stays put while the body scrolls.
 *
 * The phone sheet is a Vaul drawer (components/ui/drawer.tsx): it follows the
 * finger when swiped down, closes past a quarter of its height or on a quick
 * flick, and springs back otherwise. A swipe starts a drag only from the
 * handle and header, or from the body when the body is scrolled to its top;
 * scrolling the body, a sideways swipe, selected text, a field or the footer
 * never drags it. Swiping is a shortcut: the Close button and Esc still close.
 * Motion is transform-only and stops under `prefers-reduced-motion`.
 *
 * "View all …" / "Open full page": render `<DetailSheetFooter>` anywhere inside
 * the sheet's children (a tab component included). It is shown in a footer
 * pinned under the scrolling body, so the action is always visible, whatever
 * the length of the list above it.
 *
 * On phones the sheet has one fixed height (92% of the small viewport), like a
 * native sheet at a fixed detent: switching tabs or loading more content does
 * not make it jump, short content leaves empty space under it, and a tab change
 * starts the new tab at the top.
 */

'use client'

import * as React from 'react'
import { createPortal } from 'react-dom'
import dynamic from 'next/dynamic'
import Link from '@/components/link'
import {
  ChevronDown,
  ExternalLink,
  Maximize2,
  MoreHorizontal,
  X,
  type LucideIcon,
} from 'lucide-react'

import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { TAB_CLASS, Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useTranslation } from '@/context/i18n-provider'
import { useIsMobile } from '@/hooks/use-mobile'
import { useUrlFilter } from '@/hooks/use-url-param'
import { cn } from '@/lib/utils'
import { MetaLine } from './text-layout'

// ============================================================================
// DetailSheet — the drawer itself
// ============================================================================

/** Drawer width from `sm` up. `xl` (36rem) is the sensor drawer's. */
export type DetailSheetWidth = 'md' | 'lg' | 'xl' | '2xl'

const WIDTH: Record<DetailSheetWidth, string> = {
  md: 'sm:max-w-md',
  lg: 'sm:max-w-lg',
  xl: 'sm:max-w-xl',
  '2xl': 'sm:max-w-2xl',
}

export interface DetailSheetProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Usually a `<DetailHeader>`; it must render the sheet's title. */
  header: React.ReactNode
  /** Usually `<DetailTabs>`, shown under the header and pinned with it. */
  tabs?: React.ReactNode
  /** The active tab's name: the body is then its `tabpanel`. */
  panel?: string
  width?: DetailSheetWidth
  children?: React.ReactNode
  className?: string
  /**
   * Pinned under the scrolling body (a composer, a primary action). The body
   * scrolls between the header and this.
   */
  footer?: React.ReactNode
  /** The scrolling body, for a feature that manages its scroll position. */
  bodyRef?: React.Ref<HTMLDivElement>
  /** Extra classes for the scrolling body (e.g. its own padding). */
  bodyClassName?: string
  /** Scroll events of the body. */
  onBodyScroll?: React.UIEventHandler<HTMLDivElement>
  /**
   * Phones: `full` (default) always takes 92% of the screen, so the sheet
   * keeps one height whatever the tab or content. `auto` grows with the
   * content up to that height; keep it for a small, tab-less sheet that would
   * look empty at full height.
   */
  phoneHeight?: 'auto' | 'full'
  /**
   * Where focus goes on open. The default keeps focus on the sheet itself
   * (no field grabs it); return an element to focus it instead.
   */
  initialFocus?: () => HTMLElement | null | undefined
  /** Where focus returns on close; the element focused before opening otherwise. */
  returnFocus?: () => HTMLElement | null | undefined
}

/** Points a caller's ref (object or callback) at a node. */
function assignRef<T>(ref: React.Ref<T> | undefined, node: T | null) {
  if (typeof ref === 'function') ref(node)
  else if (ref) ref.current = node
}

// The phone sheet is a Vaul drawer (detail-sheet-phone.tsx). Vaul is about 9 KB
// gzipped and only a phone needs it, so it downloads when a phone mounts a sheet
// (below), not with every list page. The desktop drawer is a Radix sheet.
const PhoneDrawer = dynamic(() => import('./detail-sheet-phone').then((m) => m.PhoneDrawer), {
  ssr: false,
})

// The footer's mount point, owned by the sheet. A tab component renders its
// "View all" through <DetailSheetFooter>, which portals into it.
const FooterTargetContext = React.createContext<{ node: HTMLElement; pad: string } | null>(null)

/**
 * The id of the drawer body, which is the tab panel: DetailTabs points each
 * tab's aria-controls at it (the drawer renders one panel for the active tab,
 * not a Radix TabsContent per tab, so Radix's own aria-controls would name an
 * element that does not exist).
 */
const DetailPanelIdContext = React.createContext<string | null>(null)

export interface DetailSheetFooterProps {
  children: React.ReactNode
  className?: string
}

/**
 * A navigation action that belongs at the bottom of the sheet ("View all
 * findings (2)", "Open full page"). Pinned under the scrolling body with a top
 * border and the sheet's own padding, clear of the phone home indicator, and
 * last in the focus order. Outside a DetailSheet it renders in place.
 */
export function DetailSheetFooter({ children, className }: DetailSheetFooterProps) {
  const target = React.useContext(FooterTargetContext)
  const content = (
    <div
      data-slot="detail-sheet-footer"
      className={cn('border-t bg-background py-3', target?.pad, className)}
    >
      {children}
    </div>
  )
  return target ? createPortal(content, target.node) : content
}

export function DetailSheet({
  open,
  onOpenChange,
  header,
  tabs,
  panel,
  width = 'xl',
  children,
  className,
  footer,
  bodyRef,
  bodyClassName,
  onBodyScroll,
  phoneHeight = 'full',
  initialFocus,
  returnFocus,
}: DetailSheetProps) {
  // Phones get a bottom sheet you can swipe away, larger screens the side
  // drawer. Read on the first render, so an opening sheet never starts as one
  // and becomes the other.
  const isPhone = useIsMobile()
  // Warm the phone drawer's code as soon as a phone mounts a sheet, so opening
  // it does not wait on the download.
  React.useEffect(() => {
    if (isPhone) void import('./detail-sheet-phone')
  }, [isPhone])
  const pad = isPhone ? 'px-4' : 'px-5'
  const panelId = React.useId()

  // The body is ours to reset and the caller's to manage: hand the node to both.
  const scrollRef = React.useRef<HTMLDivElement | null>(null)
  const setBodyRef = React.useCallback(
    (node: HTMLDivElement | null) => {
      scrollRef.current = node
      assignRef(bodyRef, node)
    },
    [bodyRef]
  )

  // A new tab starts at its top, not wherever the previous tab was scrolled.
  // Before paint, so the new tab never flashes mid-way down.
  const lastPanel = React.useRef(panel)
  React.useLayoutEffect(() => {
    if (lastPanel.current === panel) return
    lastPanel.current = panel
    if (scrollRef.current) scrollRef.current.scrollTop = 0
  }, [panel])

  // Focus: the caller's element, or the sheet itself, so no field grabs focus
  // (and, on a phone, no keyboard slides up over the opening sheet) while the
  // focus trap still holds and screen readers start at the dialog.
  // The element focused before opening is where focus returns on close:
  // Radix returns it to a `Dialog.Trigger`, and these sheets are opened by the
  // caller's own controls.
  const opener = React.useRef<HTMLElement | null>(null)
  const onOpenAutoFocus = React.useCallback(
    (e: Event) => {
      e.preventDefault()
      const sheet = e.currentTarget as HTMLElement | null
      const active = document.activeElement
      opener.current =
        active instanceof HTMLElement && active !== document.body && !sheet?.contains(active)
          ? active
          : null
      const el = initialFocus?.()
      if (el) el.focus({ preventScroll: true })
      // Something inside already took focus (a composer focusing itself).
      else if (sheet && !sheet.contains(document.activeElement)) {
        sheet.focus({ preventScroll: true })
      }
    },
    [initialFocus]
  )
  const onCloseAutoFocus = React.useCallback(
    (e: Event) => {
      const el = returnFocus?.() ?? opener.current
      opener.current = null
      if (el && el.isConnected) {
        e.preventDefault()
        el.focus({ preventScroll: true })
      }
    },
    [returnFocus]
  )

  const [footerTarget, setFooterTarget] = React.useState<HTMLElement | null>(null)

  const footerValue = React.useMemo(
    () => (footerTarget ? { node: footerTarget, pad } : null),
    [footerTarget, pad]
  )

  const frame = (
    <FooterTargetContext.Provider value={footerValue}>
      <div className={cn('shrink-0 border-b', isPhone ? 'pt-2' : 'pt-4', pad, !tabs && 'pb-4')}>
        {header}
        <DetailPanelIdContext.Provider value={panel ? panelId : null}>
          {tabs}
        </DetailPanelIdContext.Provider>
      </div>
      <div
        ref={setBodyRef}
        id={panelId}
        data-slot="detail-sheet-body"
        onScroll={onBodyScroll}
        className={cn(
          'min-h-0 flex-1 overflow-y-auto pt-4 pb-6',
          // No scroll chaining into the page, no pull-to-refresh behind it.
          isPhone && 'overscroll-contain',
          pad,
          bodyClassName
        )}
        {...(panel ? { role: 'tabpanel', 'aria-label': panel } : {})}
      >
        {children}
      </div>
      {footer && (
        // A composer or a primary action: pressing it never drags the sheet.
        <div data-vaul-no-drag="" className={cn('shrink-0 border-t bg-background', pad)}>
          {footer}
        </div>
      )}
      {/* <DetailSheetFooter> content lands here; it brings its own border and
          vertical padding, so an empty mount point takes no space. */}
      <div ref={setFooterTarget} data-vaul-no-drag="" className="shrink-0 empty:hidden" />
    </FooterTargetContext.Provider>
  )

  if (isPhone) {
    return (
      <PhoneDrawer
        open={open}
        onOpenChange={onOpenChange}
        className={cn(
          // One height whatever the content (svh: the browser's bars never
          // cover it), clear of the home indicator.
          phoneHeight === 'auto' ? 'max-h-[92svh]' : 'h-[92svh]',
          className
        )}
        onOpenAutoFocus={onOpenAutoFocus}
        onCloseAutoFocus={onCloseAutoFocus}
      >
        {frame}
      </PhoneDrawer>
    )
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        data-slot="detail-sheet"
        className={cn(
          'flex w-full flex-col gap-0 overflow-hidden supports-[overflow:clip]:overflow-clip p-0 outline-none [&>button]:hidden',
          WIDTH[width],
          className
        )}
        onOpenAutoFocus={onOpenAutoFocus}
        onCloseAutoFocus={onCloseAutoFocus}
      >
        {frame}
      </SheetContent>
    </Sheet>
  )
}

// ============================================================================
// DetailHeader — who, its state, what it is, and what you can do
// ============================================================================

/**
 * Scroll the drawer body (not the frame) so that `el` is at its top. Use it
 * instead of `scrollIntoView`, which also scrolls the drawer frame on a phone
 * and leaves a blank band under the body.
 */
export function scrollDetailBodyTo(el: HTMLElement | null) {
  const body = el?.closest<HTMLElement>('[data-slot="detail-sheet-body"]')
  if (!el || !body) return
  const top = el.getBoundingClientRect().top - body.getBoundingClientRect().top + body.scrollTop
  body.scrollTo({ top: Math.max(0, top - 8), behavior: 'smooth' })
}

export interface DetailMenuItem {
  label: string
  icon?: LucideIcon
  onSelect: () => void
  /** Delete, revoke, …: drawn in the destructive colour. */
  destructive?: boolean
  /** A divider above this item (between everyday and destructive actions). */
  separatorBefore?: boolean
  /** Shown but not usable, with this as the reason (nothing to scan, busy). */
  disabledReason?: string
}

export interface DetailHeaderProps {
  /**
   * The record's name. It wraps onto more lines rather than being cut: it is
   * often the only identifier on screen.
   */
  title: React.ReactNode
  /** State and tags right after the title (status pill, "Platform", …). */
  badges?: React.ReactNode
  /** What it is and where: short parts on one wrapping line under the title (MetaLine, no glyph). */
  meta?: React.ReactNode[]
  /**
   * At most one primary and one outline button (style contract §8), plus a
   * muted note when the viewer cannot act. They end the line under the title,
   * beside the meta line (or the badges, moved there when there is no meta
   * line), so a control never takes a row alone.
   */
  actions?: React.ReactNode
  /**
   * Everything else (security and lifecycle actions: rotate, disable,
   * revoke, delete) goes in the `⋯` menu. No items, no menu.
   */
  menu?: DetailMenuItem[]
  /**
   * The record's own page. Adds an "Open full page" icon button beside the
   * header icons and, when the `⋯` menu has items of its own, the same entry
   * at its top (a menu never holds the one entry the icon already is). A real
   * link, so ctrl/cmd-click and middle-click open it in a new tab.
   */
  fullPageHref?: string
  onClose: () => void
}

/**
 * The header's icon buttons (`⋯`, Close): a small 32px button with the 16px
 * icon, and a 44×44 hit area around it (WCAG 2.5.5; Apple's minimum touch
 * target) from an invisible `::after`. The `gap-3` between the two keeps
 * their hit areas from overlapping.
 */
const HEADER_ICON_BUTTON = 'relative size-8 after:absolute after:-inset-1.5'

export function DetailHeader({
  title,
  badges,
  meta,
  actions,
  menu,
  fullPageHref,
  onClose,
}: DetailHeaderProps) {
  const { t } = useTranslation()
  const fullPageLabel = t('common.openFullPage', 'Open full page')
  const moreLabel = t('common.actionMenu.more', 'More actions')
  // The record's own page first, then the caller's items; a divider
  // (separatorBefore) starts a new section.
  const moreItems: ActionMenuEntry[] = []
  if (fullPageHref && (menu?.length ?? 0) > 0) {
    moreItems.push({
      id: 'full-page',
      label: fullPageLabel,
      icon: ExternalLink,
      href: fullPageHref,
      section: 'page',
    })
  }
  let section = 0
  ;(menu ?? []).forEach((item, i) => {
    if (item.separatorBefore && i > 0) section += 1
    moreItems.push({
      id: `item-${i}`,
      label: item.label,
      icon: item.icon,
      onSelect: item.onSelect,
      destructive: item.destructive,
      disabledReason: item.disabledReason,
      section: `menu-${section}`,
    })
  })
  const parts = (meta ?? []).filter((p) => p !== null && p !== undefined && p !== false && p !== '')
  const hasActions = actions !== null && actions !== undefined && actions !== false
  // Separated by space, not a glyph, and wrapping instead of cut off: on a
  // phone the last part (often the address) stays visible. text-meta here
  // too: the description's own text-sm would win.
  const metaLine =
    parts.length > 0 ? (
      <SheetDescription asChild className="text-meta">
        <MetaLine items={parts} className={cn('tabular-nums', !hasActions && 'mt-1')} />
      </SheetDescription>
    ) : null
  // The actions never take a row alone: they end the line under the title,
  // beside its facts (the meta line, or the badges when there is no meta
  // line). Only a header with neither puts them beside the header icons.
  const badgesBelow = hasActions && parts.length === 0 && !!badges
  const factsBelow = hasActions ? (metaLine ?? (badgesBelow ? badges : null)) : null
  const actionsOnTop = hasActions && !factsBelow
  const actionsGroup = (
    <div data-slot="detail-header-actions" className="flex flex-wrap items-center gap-2">
      {actions}
    </div>
  )
  return (
    <div data-slot="detail-header">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
            <SheetTitle className="min-w-0 text-lg leading-tight font-semibold break-words">
              {title}
            </SheetTitle>
            {!badgesBelow && badges}
          </div>
          {!hasActions && metaLine}
          {parts.length === 0 && (
            // Radix wants a description; keep it for screen readers only.
            <SheetDescription className="sr-only">
              {t('common.detailSheet.description', 'Details')}
            </SheetDescription>
          )}
        </div>
        <div className="-me-2 flex shrink-0 items-center gap-3">
          {actionsOnTop && actionsGroup}
          {fullPageHref && (
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button asChild variant="ghost" size="icon" className={HEADER_ICON_BUTTON}>
                    <Link href={fullPageHref} aria-label={fullPageLabel}>
                      <Maximize2 className="h-4 w-4" />
                    </Link>
                  </Button>
                </TooltipTrigger>
                <TooltipContent>{fullPageLabel}</TooltipContent>
              </Tooltip>
            </TooltipProvider>
          )}
          {moreItems.length > 0 && (
            <ActionMenu
              items={moreItems}
              title={typeof title === 'string' ? title : moreLabel}
              label={moreLabel}
              trigger={
                <Button
                  variant="ghost"
                  size="icon"
                  className={HEADER_ICON_BUTTON}
                  aria-label={moreLabel}
                >
                  <MoreHorizontal className="h-4 w-4" aria-hidden />
                </Button>
              }
            />
          )}
          <Button
            variant="ghost"
            size="icon"
            className={HEADER_ICON_BUTTON}
            aria-label={t('common.actionMenu.close', 'Close')}
            onClick={onClose}
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>
      {factsBelow && (
        // One line: the facts take what is left (at least 8rem, wrapping
        // inside it) and the actions end it. Only actions wider than the
        // rest (a toolbar of several controls) drop to the next line, as a
        // group, never one control alone.
        <div
          data-slot="detail-header-line"
          className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-2"
        >
          <div className="flex min-w-0 flex-[1_1_8rem] flex-wrap items-center gap-2">
            {factsBelow}
          </div>
          <div className="ms-auto">{actionsGroup}</div>
        </div>
      )}
    </div>
  )
}

// ============================================================================
// DetailTabs — the drawer's sub-views, optionally kept in the URL
// ============================================================================

export interface DetailTab<T extends string = string> {
  value: T
  label: React.ReactNode
}

export interface DetailTabsProps<T extends string = string> {
  tabs: DetailTab<T>[]
  value: T
  onValueChange: (value: T) => void
  className?: string
}

/**
 * The default underline tabs, keyboard operable (Radix: arrows, Home, End).
 * Controlled; `useDetailTab` keeps the value in the URL when the page wants a
 * shareable link to a tab. Tabs that do not fit the width go under a "More"
 * menu instead of being cut off; the active tab always stays visible.
 */
export function DetailTabs<T extends string>({
  tabs,
  value,
  onValueChange,
  className,
}: DetailTabsProps<T>) {
  const { t } = useTranslation()
  const panelId = React.useContext(DetailPanelIdContext)
  const stripRef = React.useRef<HTMLDivElement>(null)
  const measureRef = React.useRef<HTMLDivElement>(null)
  const fit = useTabsThatFit(stripRef, measureRef, tabs.length)

  // The tabs that fit stay in the strip; the rest go under "More". The
  // active tab is always in the strip, in place of the last one that fits.
  const activeIndex = tabs.findIndex((tab) => tab.value === value)
  let shown = tabs.slice(0, fit)
  if (fit < tabs.length && activeIndex >= fit) {
    shown = [...tabs.slice(0, Math.max(0, fit - 1)), tabs[activeIndex]]
  }
  const shownValues = new Set(shown.map((tab) => tab.value))
  const overflow = tabs.filter((tab) => !shownValues.has(tab.value))
  const moreLabel = t('common.moreTabs', 'More')

  return (
    <Tabs
      value={value}
      onValueChange={(v) => onValueChange(v as T)}
      className={cn('relative mt-3', className)}
    >
      {/* The "More" menu button sits beside the tab list, not in it: a
          tablist holds only tabs. The row carries the strip's underline. */}
      <div ref={stripRef} className="flex h-10 w-full max-w-full items-stretch gap-6 border-b">
        <TabsList className="h-auto w-auto min-w-0 flex-1 border-b-0">
          {shown.map((tab) => (
            <TabsTrigger
              key={tab.value}
              value={tab.value}
              {...(panelId ? { 'aria-controls': panelId } : {})}
            >
              {tab.label}
            </TabsTrigger>
          ))}
        </TabsList>
        {overflow.length > 0 && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button type="button" className={TAB_CLASS} data-slot="tabs-more">
                {moreLabel}
                <ChevronDown aria-hidden="true" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              {overflow.map((tab) => (
                <DropdownMenuItem key={tab.value} onSelect={() => onValueChange(tab.value)}>
                  {tab.label}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>
      {/* Every label at its natural width, out of sight, so the strip knows
          how many fit whatever is currently shown. */}
      <div
        ref={measureRef}
        aria-hidden="true"
        className="pointer-events-none invisible absolute top-0 left-0 flex h-0 gap-6 overflow-hidden whitespace-nowrap"
      >
        {tabs.map((tab) => (
          <span key={tab.value} className={TAB_CLASS}>
            {tab.label}
          </span>
        ))}
        <span className={TAB_CLASS}>
          {moreLabel}
          <ChevronDown />
        </span>
      </div>
    </Tabs>
  )
}

/** The gap between tabs in a strip (`gap-6`). */
const TAB_GAP_PX = 24

/**
 * How many tabs fit in the strip with room for a "More" button after them,
 * from the hidden row of natural-width labels; all of them when nothing can
 * be measured (server render, tests).
 */
function useTabsThatFit(
  stripRef: React.RefObject<HTMLDivElement | null>,
  measureRef: React.RefObject<HTMLDivElement | null>,
  count: number
): number {
  const [fit, setFit] = React.useState(count)
  React.useLayoutEffect(() => {
    const strip = stripRef.current
    const measure = measureRef.current
    if (!strip || !measure) return
    const compute = () => {
      const widths = Array.from(measure.children).map((c) => (c as HTMLElement).offsetWidth)
      const more = widths.pop() ?? 0
      const avail = strip.clientWidth
      const total =
        widths.reduce((sum, w) => sum + w, 0) + TAB_GAP_PX * Math.max(0, widths.length - 1)
      if (avail <= 0 || total <= avail) {
        setFit(widths.length)
        return
      }
      let used = 0
      let n = 0
      for (const w of widths) {
        const next = used + (n > 0 ? TAB_GAP_PX : 0) + w
        if (next + TAB_GAP_PX + more > avail) break
        used = next
        n++
      }
      setFit(Math.max(1, n))
    }
    compute()
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(compute)
    ro.observe(strip)
    ro.observe(measure)
    return () => ro.disconnect()
  }, [stripRef, measureRef, count])
  return fit
}

/**
 * The active drawer tab in the URL (`?<param>=…`), the first tab when the
 * parameter is absent or names no tab. The first tab is not written to the
 * URL. Pick a parameter the page does not already use for its own tabs.
 */
export function useDetailTab<T extends string>(
  param: string,
  values: readonly T[]
): [T, (next: T) => void] {
  const [raw, setRaw] = useUrlFilter(param, values[0])
  const value = (values as readonly string[]).includes(raw) ? (raw as T) : values[0]
  // Never write the tab that is already active. Radix <Tabs> is controlled, so a
  // stray onValueChange with the current value would rewrite the URL, which a
  // subscriber reflects back onto `value` — a feedback loop if the serialisation
  // round-trips imperfectly. Writing only real changes keeps the setter a no-op
  // when nothing changed.
  const setValue = React.useCallback(
    (next: T) => {
      if (next === value) return
      setRaw(next)
    },
    [setRaw, value]
  )
  return [value, setValue]
}
