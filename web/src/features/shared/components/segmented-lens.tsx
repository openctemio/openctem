'use client'

import * as React from 'react'
import { cn } from '@/lib/utils'

/**
 * A lens: a small segmented control that switches what a list is about
 * ("Open · Fixed · Dispositioned · All") without being a filter facet. One
 * value is always selected. It is a radio group: arrow keys move and select,
 * Home/End jump, only the selected segment is in the tab order.
 *
 * Counts are optional; pass `undefined` while they load (nothing is shown, so
 * the control keeps its size) and a number once known.
 */

export interface SegmentedLensOption<V extends string> {
  value: V
  label: string
  count?: number
  /** Accessible description of what the lens contains. */
  description?: string
}

export interface SegmentedLensProps<V extends string> {
  /** The group's accessible name ("Finding state"). */
  label: string
  value: V
  options: SegmentedLensOption<V>[]
  onChange: (value: V) => void
  /** What a count counts, for screen readers ("findings"). */
  countNoun?: string
  className?: string
}

const compact = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 })

export function SegmentedLens<V extends string>({
  label,
  value,
  options,
  onChange,
  countNoun = 'items',
  className,
}: SegmentedLensProps<V>) {
  const refs = React.useRef<(HTMLButtonElement | null)[]>([])
  const index = Math.max(
    0,
    options.findIndex((o) => o.value === value)
  )

  const move = (to: number) => {
    const next = (to + options.length) % options.length
    onChange(options[next].value)
    refs.current[next]?.focus()
  }

  const onKeyDown = (e: React.KeyboardEvent) => {
    switch (e.key) {
      case 'ArrowRight':
      case 'ArrowDown':
        e.preventDefault()
        move(index + 1)
        break
      case 'ArrowLeft':
      case 'ArrowUp':
        e.preventDefault()
        move(index - 1)
        break
      case 'Home':
        e.preventDefault()
        move(0)
        break
      case 'End':
        e.preventDefault()
        move(options.length - 1)
        break
    }
  }

  return (
    <div
      role="radiogroup"
      aria-label={label}
      data-testid="segmented-lens"
      onKeyDown={onKeyDown}
      className={cn('inline-flex h-8 items-center rounded-md border bg-muted/40 p-0.5', className)}
    >
      {options.map((o, i) => {
        const selected = o.value === value
        return (
          <button
            key={o.value}
            ref={(el) => {
              refs.current[i] = el
            }}
            type="button"
            role="radio"
            aria-checked={selected}
            tabIndex={selected ? 0 : -1}
            title={o.description}
            data-testid={`lens-${o.value}`}
            onClick={() => onChange(o.value)}
            className={cn(
              'inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-sm px-2.5 text-xs font-medium whitespace-nowrap transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
              selected
                ? 'bg-background text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            {o.label}
            {typeof o.count === 'number' && (
              <span
                className="tabular-nums text-muted-foreground"
                aria-label={`${o.count} ${countNoun}`}
              >
                {compact.format(o.count)}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}
