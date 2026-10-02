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
}: DetailSheetProps) {
  // Phones get a bottom sheet, larger screens the side drawer.
  const isPhone = useIsMobile()
  const pad = isPhone ? 'px-4' : 'px-5'
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side={isPhone ? 'bottom' : 'right'}
        data-slot="detail-sheet"
        className={cn(
          'flex w-full flex-col gap-0 overflow-hidden p-0 [&>button]:hidden',
          isPhone ? 'max-h-[92svh] rounded-t-2xl' : WIDTH[width],
          className
        )}
        onOpenAutoFocus={(e) => e.preventDefault()}
      >
        {isPhone && (
          <div aria-hidden className="mx-auto mt-2 h-1 w-9 shrink-0 rounded-full bg-border" />
        )}
        <div className={cn('shrink-0 border-b pt-4', pad, !tabs && 'pb-4')}>
          {header}
          {tabs}
        </div>
        <div
          className={cn('min-h-0 flex-1 overflow-y-auto pt-4 pb-6', pad)}
          {...(panel ? { role: 'tabpanel', 'aria-label': panel } : {})}
        >
          {children}
        </div>
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
        <div className="-me-2 flex shrink-0 items-center">
          {menu && menu.length > 0 && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" className="size-8" aria-label="More actions">
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
            className="size-8"
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
