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
 * On phones the sheet has one fixed height (92% of the small viewport), like a
 * native sheet at a fixed detent: switching tabs or loading more content does
 * not make it jump, short content leaves empty space under it, and a tab change
 * starts the new tab at the top.
 */

'use client'

import * as React from 'react'
import { MoreHorizontal, X } from 'lucide-react'

import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Drawer, DrawerContent, DrawerHandle } from '@/components/ui/drawer'
import { Sheet, SheetContent, SheetDescription, SheetTitle } from '@/components/ui/sheet'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useIsMobile } from '@/hooks/use-mobile'
import { useUrlFilter } from '@/hooks/use-url-param'
import { cn } from '@/lib/utils'

type IconType = React.ElementType

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

/**
 * Inputs and other controls never start a drag: dragging on a text field
 * selects text or moves the caret, a slider slides. Vaul skips any element
 * under `[data-vaul-no-drag]`, so the control under the finger is tagged as
 * the press starts, before Vaul decides.
 */
const NO_DRAG_SELECTOR =
  'input, textarea, select, [contenteditable=""], [contenteditable="true"], [role="slider"], [role="textbox"]'

function keepControlsFromDragging(e: React.PointerEvent) {
  const target = e.target
  if (!(target instanceof Element)) return
  const control = target.closest(NO_DRAG_SELECTOR)
  if (control && !control.hasAttribute('data-vaul-no-drag')) {
    control.setAttribute('data-vaul-no-drag', '')
  }
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
  const pad = isPhone ? 'px-4' : 'px-5'

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

  const frame = (
    <>
      <div className={cn('shrink-0 border-b', isPhone ? 'pt-2' : 'pt-4', pad, !tabs && 'pb-4')}>
        {header}
        {tabs}
      </div>
      <div
        ref={setBodyRef}
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
    </>
  )

  if (isPhone) {
    return (
      <Drawer open={open} onOpenChange={onOpenChange}>
        <DrawerContent
          data-slot="detail-sheet"
          className={cn(
            'w-full gap-0 overflow-hidden p-0 outline-none',
            // One height whatever the content (svh: the browser's bars never
            // cover it), clear of the home indicator.
            'rounded-t-2xl border-t pb-[env(safe-area-inset-bottom)]',
            phoneHeight === 'auto' ? 'max-h-[92svh]' : 'h-[92svh]',
            className
          )}
          onPointerDownCapture={keepControlsFromDragging}
          onOpenAutoFocus={onOpenAutoFocus}
          onCloseAutoFocus={onCloseAutoFocus}
        >
          <DrawerHandle />
          {frame}
        </DrawerContent>
      </Drawer>
    )
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        data-slot="detail-sheet"
        className={cn(
          'flex w-full flex-col gap-0 overflow-hidden p-0 outline-none [&>button]:hidden',
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

export interface DetailMenuItem {
  label: string
  icon?: IconType
  onSelect: () => void
  /** Delete, revoke, …: drawn in the destructive colour. */
  destructive?: boolean
  /** A divider above this item (between everyday and destructive actions). */
  separatorBefore?: boolean
}

export interface DetailHeaderProps {
  /**
   * The record's name. It wraps onto more lines rather than being cut: it is
   * often the only identifier on screen.
   */
  title: React.ReactNode
  /** State and tags right after the title (status pill, "Platform", …). */
  badges?: React.ReactNode
  /** What it is and where: short parts joined with " · " under the title. */
  meta?: React.ReactNode[]
  /**
   * The row under the title: at most one primary and one outline button
   * (style contract §8), plus a muted note when the viewer cannot act.
   */
  actions?: React.ReactNode
  /**
   * Everything else (security and lifecycle actions: rotate, disable,
   * revoke, delete) goes in the `⋯` menu. No items, no menu.
   */
  menu?: DetailMenuItem[]
  onClose: () => void
}

/**
 * The header's icon buttons (`⋯`, Close): a small 32px button with the 16px
 * icon, and a 44×44 hit area around it (WCAG 2.5.5; Apple's minimum touch
 * target) from an invisible `::after`. The `gap-3` between the two keeps
 * their hit areas from overlapping.
 */
const HEADER_ICON_BUTTON = 'relative size-8 after:absolute after:-inset-1.5'

export function DetailHeader({ title, badges, meta, actions, menu, onClose }: DetailHeaderProps) {
  const parts = (meta ?? []).filter((p) => p !== null && p !== undefined && p !== false && p !== '')
  return (
    <div data-slot="detail-header">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
            <SheetTitle className="min-w-0 text-lg leading-tight font-semibold break-words">
              {title}
            </SheetTitle>
            {badges}
          </div>
          {parts.length > 0 ? (
            <SheetDescription className="mt-1 truncate text-xs text-muted-foreground tabular-nums">
              {parts.map((p, i) => (
                <React.Fragment key={i}>
                  {i > 0 && ' · '}
                  {p}
                </React.Fragment>
              ))}
            </SheetDescription>
          ) : (
            // Radix wants a description; keep it for screen readers only.
            <SheetDescription className="sr-only">Details</SheetDescription>
          )}
        </div>
        <div className="-me-2 flex shrink-0 items-center gap-3">
          {menu && menu.length > 0 && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className={HEADER_ICON_BUTTON}
                  aria-label="More actions"
                >
                  <MoreHorizontal className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                {menu.map((item, i) => {
                  const Icon = item.icon
                  return (
                    <React.Fragment key={item.label}>
                      {item.separatorBefore && i > 0 && <DropdownMenuSeparator />}
                      <DropdownMenuItem
                        className={cn(
                          item.destructive && 'text-destructive focus:text-destructive'
                        )}
                        onClick={item.onSelect}
                      >
                        {Icon && <Icon className="h-4 w-4" />}
                        {item.label}
                      </DropdownMenuItem>
                    </React.Fragment>
                  )
                })}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
          <Button
            variant="ghost"
            size="icon"
            className={HEADER_ICON_BUTTON}
            aria-label="Close"
            onClick={onClose}
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>
      {actions && <div className="mt-3 flex flex-wrap items-center gap-2">{actions}</div>}
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
 * shareable link to a tab.
 */
export function DetailTabs<T extends string>({
  tabs,
  value,
  onValueChange,
  className,
}: DetailTabsProps<T>) {
  return (
    <Tabs
      value={value}
      onValueChange={(v) => onValueChange(v as T)}
      className={cn('mt-3', className)}
    >
      <TabsList>
        {tabs.map((t) => (
          <TabsTrigger key={t.value} value={t.value}>
            {t.label}
          </TabsTrigger>
        ))}
      </TabsList>
    </Tabs>
  )
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
  return [value, setRaw as (next: T) => void]
}
