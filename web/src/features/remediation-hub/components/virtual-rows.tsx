'use client'

/**
 * A windowed list: only the rows in view (plus a margin) are in the DOM, so
 * a task with ten thousand findings scrolls as fast as one with ten. Rows
 * have a fixed height; reaching the end asks for more.
 */

import { useCallback, useState, type ReactNode, type UIEvent } from 'react'

export interface VirtualRowsProps<T> {
  rows: T[]
  rowHeight: number
  height: number
  overscan?: number
  renderRow: (row: T, index: number) => ReactNode
  rowKey: (row: T, index: number) => string
  onEndReached?: () => void
  label: string
}

export function visibleRange(
  scrollTop: number,
  height: number,
  rowHeight: number,
  count: number,
  overscan: number
) {
  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan)
  const last = Math.min(count, Math.ceil((scrollTop + height) / rowHeight) + overscan)
  return { first, last }
}

export function VirtualRows<T>({
  rows,
  rowHeight,
  height,
  overscan = 8,
  renderRow,
  rowKey,
  onEndReached,
  label,
}: VirtualRowsProps<T>) {
  const [scrollTop, setScrollTop] = useState(0)
  const onScroll = useCallback(
    (e: UIEvent<HTMLDivElement>) => {
      const el = e.currentTarget
      setScrollTop(el.scrollTop)
      if (onEndReached && el.scrollTop + el.clientHeight >= el.scrollHeight - rowHeight * 4)
        onEndReached()
    },
    [onEndReached, rowHeight]
  )
  const total = rows.length * rowHeight
  const viewport = Math.min(height, Math.max(total, rowHeight))
  const { first, last } = visibleRange(scrollTop, viewport, rowHeight, rows.length, overscan)
  return (
    <div
      role="list"
      aria-label={label}
      className="overflow-y-auto"
      style={{ height: viewport }}
      onScroll={onScroll}
      data-testid="virtual-rows"
    >
      <div style={{ height: total, position: 'relative' }}>
        {rows.slice(first, last).map((row, i) => {
          const index = first + i
          return (
            <div
              key={rowKey(row, index)}
              role="listitem"
              style={{
                position: 'absolute',
                top: index * rowHeight,
                left: 0,
                right: 0,
                height: rowHeight,
              }}
            >
              {renderRow(row, index)}
            </div>
          )
        })}
      </div>
    </div>
  )
}
