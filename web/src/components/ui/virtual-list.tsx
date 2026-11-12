'use client'

/**
 * A long list of fixed-height rows that keeps only the visible rows (plus a
 * few above and below) in the DOM, so a list of thousands stays fast. The
 * scroll box is focusable (arrow keys and Page Up/Down scroll it) and is a
 * `list` whose rows are `listitem`s with their position (aria-posinset /
 * aria-setsize), so a screen reader still hears "3 of 1,000".
 *
 *   <VirtualList items={rows} rowHeight={52} maxHeight={320} label="Targets"
 *     getKey={(r) => r.key} renderRow={(r) => <Row row={r} />} />
 */

import * as React from 'react'
import { cn } from '@/lib/utils'

interface VirtualListProps<T> {
  items: readonly T[]
  /** Every row's height in px (rows must not grow). */
  rowHeight: number
  /** The box's largest height in px; a shorter list is as tall as its rows. */
  maxHeight: number
  getKey: (item: T, index: number) => string
  renderRow: (item: T, index: number) => React.ReactNode
  /** Accessible name of the list. */
  label: string
  /** Rows rendered beyond the visible ones, above and below. */
  overscan?: number
  className?: string
  'data-testid'?: string
}

export function VirtualList<T>({
  items,
  rowHeight,
  maxHeight,
  getKey,
  renderRow,
  label,
  overscan = 6,
  className,
  ...rest
}: VirtualListProps<T>) {
  const [scrollTop, setScrollTop] = React.useState(0)
  const total = items.length * rowHeight
  const height = Math.min(maxHeight, total)
  const visible = Math.ceil(maxHeight / rowHeight)
  // A list that shrank under the scroll position starts from its end.
  const top = Math.min(scrollTop, Math.max(0, total - height))
  const first = Math.max(0, Math.floor(top / rowHeight) - overscan)
  const last = Math.min(items.length, first + visible + overscan * 2)

  const rows: React.ReactNode[] = []
  for (let i = first; i < last; i++) {
    rows.push(
      <div
        key={getKey(items[i], i)}
        role="listitem"
        aria-posinset={i + 1}
        aria-setsize={items.length}
        className="absolute inset-x-0"
        style={{ top: i * rowHeight, height: rowHeight }}
      >
        {renderRow(items[i], i)}
      </div>
    )
  }

  return (
    <div
      role="list"
      aria-label={label}
      tabIndex={0}
      className={cn(
        'relative overflow-y-auto overscroll-contain rounded-md focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-hidden',
        className
      )}
      style={{ height }}
      onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
      data-testid={rest['data-testid']}
    >
      <div style={{ height: total }} className="relative">
        {rows}
      </div>
    </div>
  )
}
