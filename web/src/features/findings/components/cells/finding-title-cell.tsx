'use client'

import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { toDisplayText } from '@/lib/untrusted-text'
import { middleEllipsis } from '@/lib/middle-ellipsis'

/**
 * How a finding reads wherever findings are listed: the stored title is the
 * issue, and the target it was found on (host[:port], a URL or a file) is a
 * muted line under it. Two findings of one issue on two hosts used to show
 * the same line twice ("CVE-2019-9516 in nginx 1.15.5" for each asset); the
 * target line is what tells them apart.
 *
 * Every value is scanner-supplied text: it is escaped (toDisplayText) and
 * rendered as React text, never markup. The cell holds no focusable element,
 * so it can sit inside the row's own button or link; the full target is in
 * the `title` tooltip and in `targetLabel` for the row's accessible name.
 *
 * Every list of findings uses this cell (finding-title-cell-usage.test.ts).
 */
export interface FindingTitleCellProps {
  title: string | null | undefined
  /** Where the finding is: `findingLocation(f).full`, or a host, URL or path. Empty hides the line. */
  target?: string | null
  /** After the title (duplicates, branch-only, path chips). */
  chips?: ReactNode
  /** After the target (internet-facing, crown-jewel markers). */
  markers?: ReactNode
  /** A third line (CVE link, scanner). */
  meta?: ReactNode
  /** Title lines before it is cut: 1 in tables, 2 on cards. */
  titleLines?: 1 | 2
  /**
   * Makes the title the control that opens the finding: a button whose name
   * starts with the visible title (`openLabel`), so the chips, target and
   * meta (which may hold links) stay outside it.
   */
  onOpen?: () => void
  /** The open button's accessible name; it must contain the visible title. */
  openLabel?: string
  className?: string
}

/** Longest target shown; a longer one is cut from the middle (the full value is in the tooltip). */
export const TARGET_MIDDLE = 120

/**
 * Characters at the end of a target that stay visible however narrow the
 * cell is: the end of a URL or path is where two targets usually differ, so
 * the line is cut in the middle by CSS rather than at the end.
 */
export const TARGET_TAIL = 18

/** The target as shown: escaped, cut from the middle when long. */
export function shownTarget(target: string | null | undefined): string {
  const raw = (target ?? '').trim()
  if (!raw) return ''
  return middleEllipsis(toDisplayText(raw, 2000), TARGET_MIDDLE)
}

export function FindingTitleCell({
  title,
  target,
  chips,
  markers,
  meta,
  titleLines = 1,
  onOpen,
  openLabel,
  className,
}: FindingTitleCellProps) {
  const full = toDisplayText((target ?? '').trim(), 2000)
  const shown = shownTarget(target)
  const titleClass = cn(
    'min-w-0 font-medium [unicode-bidi:isolate]',
    titleLines === 2 ? 'line-clamp-2' : 'truncate'
  )
  return (
    <div data-slot="finding-title-cell" className={cn('flex min-w-0 flex-col', className)}>
      <div className="flex min-w-0 items-center gap-1.5">
        {onOpen ? (
          <button
            type="button"
            dir="auto"
            className={cn(
              titleClass,
              'rounded-sm text-start hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none'
            )}
            aria-label={openLabel}
            onClick={(e) => {
              e.stopPropagation()
              onOpen()
            }}
          >
            {toDisplayText(title ?? '', 500)}
          </button>
        ) : (
          <p dir="auto" className={titleClass}>
            {toDisplayText(title ?? '', 500)}
          </p>
        )}
        {chips}
      </div>
      {(shown || markers) && (
        <div className="flex min-w-0 items-center gap-1">
          {shown && (
            <span
              dir="auto"
              data-slot="finding-target"
              title={full}
              className="min-w-0 truncate text-xs text-muted-foreground [unicode-bidi:isolate]"
            >
              {shown.length > TARGET_TAIL + 8 ? (
                <span className="flex min-w-0">
                  <span className="min-w-0 truncate">{shown.slice(0, -TARGET_TAIL)}</span>
                  <span className="shrink-0">{shown.slice(-TARGET_TAIL)}</span>
                </span>
              ) : (
                shown
              )}
            </span>
          )}
          {markers}
        </div>
      )}
      {meta}
    </div>
  )
}
