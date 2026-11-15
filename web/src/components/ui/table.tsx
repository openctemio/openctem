'use client'

import * as React from 'react'

import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'

/**
 * Two ways to hold a table (docs/ui-style-contract.md, "Tables"):
 * - `scroll` (default): the container scrolls; it is a named region in the
 *   tab order, so a table wider than its container (a phone) can be scrolled
 *   with the keyboard (WCAG 2.1.1).
 * - `clip`: the table fits its frame and the page scrolls, so the header can
 *   stick under the app header. The container is no scroller (overflow clip
 *   creates none) and no region.
 */
function Table({
  className,
  scroll = 'scroll',
  containerStyle,
  ...props
}: React.ComponentProps<'table'> & {
  scroll?: 'scroll' | 'clip'
  containerStyle?: React.CSSProperties
}) {
  const { t } = useTranslation()
  const scrolls = scroll === 'scroll'
  return (
    <div
      data-slot="table-container"
      data-scroll={scroll}
      role={scrolls ? 'region' : undefined}
      tabIndex={scrolls ? 0 : undefined}
      aria-label={scrolls ? t('common.table.scrollRegion', 'Table, scrollable') : undefined}
      style={containerStyle}
      className={cn(
        'relative w-full',
        scrolls
          ? 'overflow-auto focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring'
          : 'overflow-x-clip'
      )}
    >
      <table
        data-slot="table"
        className={cn('w-full caption-bottom text-dense', className)}
        {...props}
      />
    </div>
  )
}

function TableHeader({ className, ...props }: React.ComponentProps<'thead'>) {
  // The header/body edge is the one structural line (--border); rows are
  // divided by the lighter --border-subtle. The header row never tints.
  return (
    <thead
      data-slot="table-header"
      className={cn(
        '[&_tr]:border-b [&_tr]:border-border [&_tr]:hover:bg-transparent [&_tr]:focus-within:bg-transparent',
        className
      )}
      {...props}
    />
  )
}

function TableBody({ className, ...props }: React.ComponentProps<'tbody'>) {
  return (
    <tbody
      data-slot="table-body"
      className={cn('[&_tr:last-child]:border-0', className)}
      {...props}
    />
  )
}

function TableFooter({ className, ...props }: React.ComponentProps<'tfoot'>) {
  return (
    <tfoot
      data-slot="table-footer"
      className={cn('bg-muted/50 border-t font-medium [&>tr]:last:border-b-0', className)}
      {...props}
    />
  )
}

function TableRow({ className, ...props }: React.ComponentProps<'tr'>) {
  return (
    <tr
      data-slot="table-row"
      className={cn(
        'border-b border-border-subtle transition-colors hover:bg-hov focus-within:bg-hov data-[state=selected]:bg-sel',
        className
      )}
      {...props}
    />
  )
}

function TableHead({ className, ...props }: React.ComponentProps<'th'>) {
  return (
    <th
      data-slot="table-head"
      scope="col"
      className={cn(
        'h-th px-1.5 text-start align-middle text-cap-m whitespace-nowrap text-muted-foreground first:ps-3 last:pe-3 [&:has([role=checkbox])]:pe-0 [&>[role=checkbox]]:translate-y-[2px]',
        className
      )}
      {...props}
    />
  )
}

function TableCell({ className, ...props }: React.ComponentProps<'td'>) {
  return (
    <td
      data-slot="table-cell"
      className={cn(
        'h-row px-1.5 py-1 align-middle first:ps-3 last:pe-3 [&:has([role=checkbox])]:pe-0 [&>[role=checkbox]]:translate-y-[2px]',
        className
      )}
      {...props}
    />
  )
}

function TableCaption({ className, ...props }: React.ComponentProps<'caption'>) {
  return (
    <caption
      data-slot="table-caption"
      className={cn('text-muted-foreground mt-4 text-body', className)}
      {...props}
    />
  )
}

export { Table, TableHeader, TableBody, TableFooter, TableHead, TableRow, TableCell, TableCaption }
