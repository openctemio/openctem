'use client'

/**
 * The header of a record's own page (a finding, an asset, a scan): what the
 * record is and what the viewer can do with it.
 *
 *   ‹ Findings                                    ‹ 3 of 31 ›     (below 768 px)
 *   [type] [CVE] [CWE]                             ‹ 2 of 27 ›     (from 768 px)
 *   Title of the record                [More] [secondary] [primary]
 *
 * On a phone the buttons take a full-width row under the title (the main
 * action first); More closes the last row with the secondary actions, never alone;
 * a More with no buttons stays at the end of the title's line.
 *
 * One primary action, at most two secondary ones, everything else in the
 * More menu (docs/ui-style-contract.md, "Detail pages"). Status, owner and
 * dates are not here: they are rows of the page's `PropertyList`.
 *
 * The root is the page's `page-header` block, so `PageStack` keeps the tab
 * strip 16 px under it, and the title is the page's only `h1`.
 */

import { useRef, type ReactNode } from 'react'
import { ChevronLeft, MoreHorizontal } from 'lucide-react'

import Link from '@/components/link'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { Button } from '@/components/ui/button'
import { usePhoneBarTitle } from '@/components/layout/phone-bar-title'
import { useTranslation } from '@/context/i18n-provider'
import { safeHref } from '@/lib/safe-href'
import { cn } from '@/lib/utils'
import { PAGE_TITLE_ID } from '../page-header'

export interface DetailPageParent {
  /** The list the record belongs to (an internal path, with its filters when known). */
  href: string
  /** The list's name, e.g. "Findings". */
  label: string
}

export interface DetailPageHeaderProps {
  title: string
  /** Where "‹ Parent" leads on a phone; the top bar's breadcrumb says it from 768 px. */
  parent: DetailPageParent
  /** Type, identifiers and state marks above the title (tags, links, badges). */
  chips?: ReactNode
  /** A line of facts under the title (owner, due date, a short description). */
  facts?: ReactNode
  /** A `DetailPosition`: previous, "n of N", next. */
  position?: ReactNode
  /** The one main action for the record's current state (a default `Button`). */
  primary?: ReactNode
  /** At most two outline buttons. */
  secondary?: ReactNode
  /** Every other action (two or more: a menu never holds one item). No items, no menu. */
  menu?: ActionMenuEntry[]
  className?: string
}

export function DetailPageHeader({
  title,
  parent,
  chips,
  position,
  facts,
  primary,
  secondary,
  menu,
  className,
}: DetailPageHeaderProps) {
  const { t } = useTranslation()
  const titleRef = useRef<HTMLHeadingElement>(null)
  usePhoneBarTitle(titleRef, title)
  const moreLabel = t('common.actionMenu.more', 'More actions')
  const hasButtons = !!primary || !!secondary
  const hasActions = hasButtons || (menu?.length ?? 0) > 0

  return (
    <header
      data-slot="page-header"
      data-kind="detail"
      className={cn('flex min-w-0 flex-col gap-2', className)}
    >
      {/* Phone: the way back and the place in the list share the first line. */}
      <div
        data-slot="detail-back-row"
        className="flex min-h-control-touch items-center justify-between gap-2 md:hidden"
      >
        <Link
          href={safeHref(parent.href) ?? '/'}
          data-slot="detail-back"
          className="-ms-1 inline-flex min-h-touch-target min-w-0 items-center gap-1 text-body font-medium text-foreground hover:underline"
        >
          <ChevronLeft className="size-4 shrink-0 rtl:rotate-180" aria-hidden />
          <span className="truncate">{parent.label}</span>
        </Link>
        {position}
      </div>

      {(chips || position) && (
        <div
          data-slot="detail-chip-row"
          className="flex min-w-0 items-start justify-between gap-x-4 gap-y-2"
        >
          <div
            data-slot="detail-chips"
            className="flex min-h-6 min-w-0 flex-1 flex-wrap items-center gap-1.5"
          >
            {chips}
          </div>
          {position && <div className="shrink-0 max-md:hidden">{position}</div>}
        </div>
      )}

      <div className="flex min-w-0 flex-wrap items-start justify-between gap-x-4 gap-y-3">
        <h1
          id={PAGE_TITLE_ID}
          ref={titleRef}
          className={cn(
            'min-w-0 flex-1 basis-60 text-page tracking-tight break-words text-balance',
            !hasButtons && 'max-md:basis-0'
          )}
        >
          {title}
        </h1>
        {hasActions && (
          <div
            data-slot="detail-actions"
            // Phone: the buttons take their own full-width row under the
            // title; More alone stays at the end of the title's line.
            className={cn(
              'flex max-w-full shrink-0 flex-wrap items-center gap-2',
              hasButtons && 'max-md:w-full'
            )}
          >
            {/* Phone: the secondary actions and More are one nowrap group, so a
                wrapped row never leaves More alone; long labels shrink. More stays
                first in the DOM (desktop and focus order) and moves last on a phone. */}
            <div
              data-slot="detail-secondary"
              className="flex min-w-0 items-center gap-2 max-md:order-last max-md:max-w-full md:contents [&>*]:min-w-0"
            >
              {menu && menu.length > 0 && (
                <div data-slot="detail-more" className="flex shrink-0 max-md:order-last">
                  <ActionMenu
                    items={menu}
                    title={title}
                    label={moreLabel}
                    trigger={
                      <Button variant="ghost" size="icon" aria-label={moreLabel}>
                        <MoreHorizontal aria-hidden />
                      </Button>
                    }
                  />
                </div>
              )}
              {secondary}
            </div>
            {primary && (
              // Phone: the main action leads the row and takes the free width;
              // it never shrinks below its label (the row wraps instead).
              <div
                data-slot="detail-primary"
                className="flex max-md:order-first max-md:min-w-fit max-md:flex-1 max-md:[&>*]:w-full"
              >
                {primary}
              </div>
            )}
          </div>
        )}
      </div>
      {facts && (
        <div data-slot="detail-facts" className="flex min-w-0 flex-col gap-1">
          {facts}
        </div>
      )}
    </header>
  )
}
