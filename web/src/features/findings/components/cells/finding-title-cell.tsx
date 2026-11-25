'use client'

import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'
import { toDisplayText } from '@/lib/untrusted-text'
import { maskSensitiveText } from '@/lib/mask-sensitive'
import { middleEllipsis } from '@/lib/middle-ellipsis'
import { RowNameLink } from '@/features/shared/components/row-name-link'
import { findingDetailHref } from '@/features/findings/lib/finding-link'

/**
 * How a finding reads wherever findings are listed: the stored title is the
 * issue, and the target it was found on (host[:port], a URL or a file) is a
 * muted line under it. Two findings of one issue on two hosts used to show
 * the same line twice ("CVE-2019-9516 in nginx 1.15.5" for each asset); the
 * target line is what tells them apart.
 *
 * Every value is scanner-supplied text: e-mail addresses and secrets in it
 * are masked (maskSensitiveText; a list never shows one in clear, "Show" is on
 * the finding page), then it is escaped (toDisplayText) and rendered as React
 * text, never markup. The title, its tooltip, `openLabel` and the target all
 * go through the mask here, so every list that uses the cell has it. The cell holds no focusable element,
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
  /**
   * With `onOpen`: the title is a real link to this finding's page
   * (`findingDetailHref`: the id is only an encoded segment under
   * `/findings/`). A plain click calls `onOpen` (the drawer);
   * Ctrl/Cmd/Shift-click, a middle click and "Open in new tab" are the
   * browser's, so the page opens in a new tab.
   */
  findingId?: string
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

/** The target as shown: masked, escaped, cut from the middle when long. */
export function shownTarget(target: string | null | undefined): string {
  const raw = maskSensitiveText(target).trim()
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
  findingId,
  className,
}: FindingTitleCellProps) {
  const full = toDisplayText(maskSensitiveText(target).trim(), 2000)
  // Masked before it is cut: half a value no longer has the shape that names it.
  const shownTitle = toDisplayText(maskSensitiveText(title), 500)
  // The whole title on pointer hover when one line cuts it (its name holds it too).
  const tip = titleLines === 1 ? shownTitle : undefined
  const openName = openLabel ? maskSensitiveText(openLabel) : undefined
  const shown = shownTarget(target)
  const titleClass = cn(
    'min-w-0 font-medium [unicode-bidi:isolate]',
    titleLines === 2 ? 'line-clamp-2' : 'truncate'
  )
  return (
    <div data-slot="finding-title-cell" className={cn('flex min-w-0 flex-col', className)}>
      <div className="flex min-w-0 items-center gap-1.5">
        {onOpen && findingId ? (
          <RowNameLink
            href={findingDetailHref(findingId)}
            onOpen={onOpen}
            label={openName}
            title={tip}
            lines={titleLines}
            slot="finding-title-link"
          >
            {shownTitle}
          </RowNameLink>
        ) : onOpen ? (
          <button
            type="button"
            dir="auto"
            // A title cut to one or two lines keeps its whole text reachable.
            title={shownTitle}
            data-cut-tooltip=""
            className={cn(
              titleClass,
              'rounded-sm text-start hover:underline focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none'
            )}
            aria-label={openName}
            onClick={(e) => {
              e.stopPropagation()
              onOpen()
            }}
          >
            {shownTitle}
          </button>
        ) : (
          <p dir="auto" title={shownTitle} data-cut-tooltip="" className={titleClass}>
            {shownTitle}
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
              // Cut in the middle on purpose (its end stays): the whole target is the title.
              data-cut-tooltip=""
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
