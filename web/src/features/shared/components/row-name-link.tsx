'use client'

import type { MouseEvent, ReactNode } from 'react'
import Link from '@/components/link'
import { safeInternalHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'

/**
 * Whether a click is the plain one (primary button, no modifier key). A
 * modified click (Ctrl, Cmd, Shift, Alt) and a middle click are the
 * browser's: they open the link in a new tab or window.
 */
export function isPlainClick(
  e: Pick<MouseEvent, 'button' | 'metaKey' | 'ctrlKey' | 'shiftKey' | 'altKey'>
): boolean {
  return e.button === 0 && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey
}

export interface RowNameLinkProps {
  /**
   * The row's detail page, a path of this app. Build it with a route builder
   * (an encoded id under a fixed path), never from raw row data; a value that
   * is not a same-origin path is not followed.
   */
  href: string
  /** A plain click: open the row's detail overlay instead of navigating. */
  onOpen: () => void
  /** Accessible name; it must contain the visible name. Default: the content. */
  label?: string
  /** The full text, shown on pointer hover when the cell cuts the name. */
  title?: string
  /** Lines before the name is cut: 1 in a table (default), 2 on a card. */
  lines?: 1 | 2
  /** `data-slot` of the link. Default "row-name-link". */
  slot?: string
  className?: string
  /** The name, already escaped where it is untrusted text (`toDisplayText`). */
  children: ReactNode
}

/**
 * A row's name in a list: a real link to the row's detail page. A plain click
 * opens the detail overlay (`onOpen`) and does not navigate; a modified or
 * middle click, and the browser's "Open in new tab", follow the link. The
 * click never reaches the row, so the row does not open the overlay as well.
 * The link shrinks with its cell and ends in an ellipsis, alone in a cell or
 * in a flex row, with no wrapper from the page; it is never prefetched (a
 * list holds one per row).
 */
export function RowNameLink({
  href,
  onOpen,
  label,
  title,
  lines = 1,
  slot = 'row-name-link',
  className,
  children,
}: RowNameLinkProps) {
  return (
    <Link
      // A page of this app only: anything else leads nowhere.
      href={safeInternalHref(href) ?? '#'}
      prefetch={false}
      dir="auto"
      data-slot={slot}
      title={title}
      aria-label={label}
      className={cn(
        'min-w-0 rounded-sm text-start font-medium [unicode-bidi:isolate] hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none focus-visible:ring-inset',
        // One line: an inline box no wider than its cell, so the name ends in
        // an ellipsis alone in a cell too (an inline anchor never cuts).
        lines === 2 ? 'line-clamp-2' : 'inline-block max-w-full truncate align-bottom',
        className
      )}
      onClick={(e) => {
        // The row must not open the overlay as well.
        e.stopPropagation()
        if (!isPlainClick(e)) return
        e.preventDefault()
        onOpen()
      }}
    >
      {children}
    </Link>
  )
}
