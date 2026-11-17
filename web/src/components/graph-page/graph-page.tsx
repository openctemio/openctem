'use client'

/**
 * The shared parts of a graph page (attack paths, exposure chains, exploration,
 * the scan workflow editor): under the page's title row, one toolbar, then the
 * graph filling the rest of the window. The legend and the scoring notes open
 * from the toolbar as popovers, and the detail of a node opens as a sheet over
 * the page, so no panel stands beside the graph. Each page keeps an equivalent
 * list or table of what the graph shows, switched with `graphViewOptions`.
 */

import * as React from 'react'
import { CircleHelp, List, Network, type LucideIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'

export type GraphView = 'graph' | 'list'

/** The two views every graph page has: the graph, and the same content as rows. */
export function useGraphViewOptions(): { value: GraphView; label: string; icon: LucideIcon }[] {
  const { t } = useTranslation()
  return React.useMemo(
    () => [
      { value: 'graph' as const, label: t('common.graph.viewGraph', 'Graph'), icon: Network },
      { value: 'list' as const, label: t('common.graph.viewList', 'List view'), icon: List },
    ],
    [t]
  )
}

/**
 * The one toolbar of a graph page: the filters at the start, the legend, notes
 * and other canvas actions at the end. Wraps instead of scrolling sideways.
 */
export function GraphToolbar({
  label,
  children,
  end,
  className,
}: {
  /** Accessible name, e.g. "Attack path filters". */
  label: string
  children?: React.ReactNode
  end?: React.ReactNode
  className?: string
}) {
  return (
    <div
      role="toolbar"
      aria-label={label}
      data-slot="graph-toolbar"
      className={cn('flex flex-wrap items-center gap-2', className)}
    >
      {children}
      {end && <div className="ms-auto flex flex-wrap items-center gap-2">{end}</div>}
    </div>
  )
}

export interface GraphLegendItem {
  key: string
  /** The mark as drawn on the graph; decorative, the label names it. */
  mark: React.ReactNode
  label: string
}

/** The marks of a legend as a list (inside the popover, or inline in a full-screen graph). */
export function GraphLegendList({
  items,
  className,
  testId,
}: {
  items: GraphLegendItem[]
  className?: string
  testId?: string
}) {
  const { t } = useTranslation()
  return (
    <ul
      className={cn('grid gap-2 text-dense text-muted-foreground', className)}
      aria-label={t('common.graph.legend', 'Legend')}
      data-testid={testId}
    >
      {items.map((i) => (
        <li key={i.key} className="flex items-center gap-2">
          <span aria-hidden className="flex w-6 shrink-0 items-center justify-center">
            {i.mark}
          </span>
          <span className="min-w-0">{i.label}</span>
        </li>
      ))}
    </ul>
  )
}

/** The legend of a graph, opened from the toolbar. */
export function GraphLegend({ items, testId }: { items: GraphLegendItem[]; testId?: string }) {
  const { t } = useTranslation()
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button type="button" variant="outline" data-testid="graph-legend-trigger">
          {t('common.graph.legend', 'Legend')}
        </Button>
      </PopoverTrigger>
      <PopoverContent>
        <p className="mb-2 text-card-title">{t('common.graph.legend', 'Legend')}</p>
        <GraphLegendList items={items} testId={testId} />
      </PopoverContent>
    </Popover>
  )
}

/** A note on how the graph is built or scored, opened from the toolbar. */
export function GraphNote({
  label,
  title,
  children,
}: {
  /** The trigger's text, e.g. "How a path is scored". */
  label: string
  title: string
  children: React.ReactNode
}) {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button type="button" variant="ghost" data-testid="graph-note-trigger">
          <CircleHelp aria-hidden />
          {label}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-80 text-dense">
        <p className="text-card-title">{title}</p>
        <div className="mt-2 grid gap-2 text-muted-foreground">{children}</div>
      </PopoverContent>
    </Popover>
  )
}

/**
 * The frame of the graph: a bordered surface that takes what is left of the
 * window under the title row and the toolbar, never less than a readable
 * height. `footer` is the line of facts under the graph (when it was computed,
 * what is shown).
 */
export function GraphFrame({
  label,
  children,
  footer,
  fill = true,
  className,
  testId,
}: {
  label: string
  children: React.ReactNode
  footer?: React.ReactNode
  /** False for content that has its own height (the list view). */
  fill?: boolean
  className?: string
  testId?: string
}) {
  return (
    <section
      aria-label={label}
      data-slot="graph-frame"
      data-fill={fill ? 'true' : undefined}
      data-testid={testId}
      className={cn(
        'flex min-w-0 flex-col overflow-hidden rounded-lg border bg-card',
        // What the shell, the title row and the toolbar take is about 15rem
        // (13rem on a phone); the graph gets the rest.
        fill && 'h-[calc(100dvh-13rem)] min-h-96 md:h-[calc(100dvh-15rem)] md:min-h-[30rem]',
        className
      )}
    >
      <div className={cn('min-w-0', fill && 'flex min-h-0 flex-1 flex-col')}>{children}</div>
      {footer && (
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 border-t border-border-subtle px-4 py-2 text-cap text-muted-foreground">
          {footer}
        </div>
      )}
    </section>
  )
}

/**
 * The detail of one node, over the page. Closing it (Esc, the close button, a
 * click outside) returns focus to the node or row that opened it.
 */
export function GraphNodeSheet({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  testId = 'graph-node-sheet',
  returnFocus,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: React.ReactNode
  description?: React.ReactNode
  children: React.ReactNode
  footer?: React.ReactNode
  testId?: string
  /**
   * The node or row that opened the sheet, looked up when it closes: a graph
   * may redraw its nodes while the sheet is open, so the element that had
   * focus then can be gone.
   */
  returnFocus?: () => HTMLElement | null
}) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        data-testid={testId}
        onCloseAutoFocus={(e) => {
          const el = returnFocus?.()
          if (el?.isConnected) {
            e.preventDefault()
            el.focus()
          }
        }}
      >
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
          {description && <SheetDescription>{description}</SheetDescription>}
        </SheetHeader>
        <SheetBody>{children}</SheetBody>
        {footer && <SheetFooter>{footer}</SheetFooter>}
      </SheetContent>
    </Sheet>
  )
}
