'use client'

import { Column } from '@tanstack/react-table'
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react'
import { cn } from '@/lib/utils'
import { columnLayout } from './column-meta'

interface DataTableColumnHeaderProps<TData, TValue> extends React.HTMLAttributes<HTMLDivElement> {
  column: Column<TData, TValue>
  title: string
}

/**
 * A column header. A sortable one is one button: a click sorts by the column
 * (its natural first direction, `meta.sortFirst` or the kind's), the next
 * click turns the direction. The arrow shows only on the sorted column; the
 * others show a faint one on hover and focus. Hiding a column lives in the
 * table's Display menu. `aria-sort` sits on the header cell (DataTable).
 */
export function DataTableColumnHeader<TData, TValue>({
  column,
  title,
  className,
}: DataTableColumnHeaderProps<TData, TValue>) {
  const layout = columnLayout(column.id, column.columnDef.meta)
  const end = layout.align === 'end'
  if (!column.getCanSort()) {
    return (
      <div className={cn('truncate', end && 'text-end', className)} title={title}>
        {title}
      </div>
    )
  }
  const sorted = column.getIsSorted()
  const Arrow = sorted === 'desc' ? ArrowDown : sorted === 'asc' ? ArrowUp : ArrowUpDown
  const arrow = (
    <Arrow
      aria-hidden="true"
      data-slot="sort-arrow"
      className={cn(
        'size-3.5 shrink-0',
        sorted
          ? 'text-foreground'
          : 'opacity-0 group-hover/sort:opacity-55 group-focus-visible/sort:opacity-55'
      )}
    />
  )
  return (
    <div className={cn('flex min-w-0', end && 'justify-end', className)}>
      <button
        type="button"
        data-slot="sort-button"
        title={title}
        onClick={() => {
          if (sorted) column.toggleSorting(sorted === 'asc')
          else column.toggleSorting(layout.sortFirst === 'desc')
        }}
        className={cn(
          // 28 tall ghost target; the -mx keeps the label on the column's edge.
          'group/sort -mx-2 inline-flex h-7 min-w-0 items-center gap-1 rounded-md px-2 text-cap-m transition-colors hover:bg-hov focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
          sorted ? 'text-foreground' : 'text-muted-foreground'
        )}
      >
        {end && arrow}
        <span className="truncate">{title}</span>
        {!end && arrow}
      </button>
    </div>
  )
}
