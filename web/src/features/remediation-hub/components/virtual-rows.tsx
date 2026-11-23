'use client'

/**
 * A windowed list: only the rows in view (plus a margin) are in the DOM, so
 * a task with ten thousand findings scrolls as fast as one with ten. Each row
 * has a known height (one number, or one per kind of row, so a group heading
 * can stay short while a finding takes two lines on a phone); reaching the
 * end asks for more.
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
  type UIEvent,
} from 'react'

export interface VirtualRowsProps<T> {
  rows: T[]
  /** One height for every row, or the height of each row. */
  rowHeight: number | ((row: T) => number)
  height: number
  overscan?: number
  renderRow: (row: T, index: number) => ReactNode
  rowKey: (row: T, index: number) => string
  onEndReached?: () => void
  label: string
  /** Scrolls this row into view when it changes (keyboard navigation). */
  scrollToIndex?: number | null
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

/** The top of every row, plus the total height as the last entry. */
export function rowOffsets(heights: number[]): number[] {
  const out = new Array<number>(heights.length + 1)
  out[0] = 0
  for (let i = 0; i < heights.length; i++) out[i + 1] = out[i] + heights[i]
  return out
}

/** The last row whose top is at or above `y` (binary search over the offsets). */
function rowAt(offsets: number[], y: number): number {
  let lo = 0
  let hi = offsets.length - 2
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1
    if (offsets[mid] <= y) lo = mid
    else hi = mid - 1
  }
  return Math.max(0, lo)
}

/** Like `visibleRange`, for rows of different heights. */
export function visibleRangeAt(
  offsets: number[],
  scrollTop: number,
  height: number,
  overscan: number
) {
  const count = offsets.length - 1
  if (count <= 0) return { first: 0, last: 0 }
  const first = Math.max(0, rowAt(offsets, scrollTop) - overscan)
  const last = Math.min(count, rowAt(offsets, scrollTop + height) + 1 + overscan)
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
  scrollToIndex,
}: VirtualRowsProps<T>) {
  const [scrollTop, setScrollTop] = useState(0)
  const box = useRef<HTMLDivElement>(null)
  const offsets = useMemo(
    () => rowOffsets(rows.map((r) => (typeof rowHeight === 'number' ? rowHeight : rowHeight(r)))),
    [rows, rowHeight]
  )
  const total = offsets[offsets.length - 1]
  const tail = rows.length ? total / rows.length : 0
  useEffect(() => {
    const el = box.current
    if (!el || scrollToIndex == null || scrollToIndex < 0 || scrollToIndex >= rows.length) return
    const top = offsets[scrollToIndex]
    const bottom = offsets[scrollToIndex + 1]
    if (top < el.scrollTop) el.scrollTop = top
    else if (bottom > el.scrollTop + el.clientHeight) el.scrollTop = bottom - el.clientHeight
  }, [scrollToIndex, offsets, rows.length])
  const onScroll = useCallback(
    (e: UIEvent<HTMLDivElement>) => {
      const el = e.currentTarget
      setScrollTop(el.scrollTop)
      if (onEndReached && el.scrollTop + el.clientHeight >= el.scrollHeight - tail * 4)
        onEndReached()
    },
    [onEndReached, tail]
  )
  const viewport = Math.min(height, Math.max(total, tail))
  const { first, last } = visibleRangeAt(offsets, scrollTop, viewport, overscan)
  return (
    <div
      ref={box}
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
                top: offsets[index],
                left: 0,
                right: 0,
                height: offsets[index + 1] - offsets[index],
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
