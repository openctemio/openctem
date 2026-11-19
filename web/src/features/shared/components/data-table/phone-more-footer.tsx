'use client'

import * as React from 'react'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { nextPhonePageSize } from '@/lib/page-size-options'
import { formatNumber } from '@/lib/app-locale'

/** One card of a phone list (`data-phone-card`), so the footer can focus the first new one. */
const PHONE_CARD_SELECTOR = '[data-phone-card]'

interface PhoneMoreFooterProps {
  /** Cards on screen. */
  shown: number
  /** Rows behind the list; leave out when the count failed or stopped at a cap. */
  total?: number
  pageIndex: number
  pageSize: number
  /** With no `total`: false when the list knows this is its last page. */
  mayHaveMore?: boolean
  /** The largest page size the list's API returns; none for a list paged in the browser. */
  maxPageSize?: number
  onPageSizeChange: (pageSize: number) => void
  /** A phone list is one growing page: a link to a later page opens the first. */
  onFirstPage: () => void
  /** A read is running: the button waits for it. */
  busy?: boolean
  /** The element that holds the cards. */
  cardsRef: React.RefObject<HTMLElement | null>
  /** Shown before the count (how old the rows are). */
  note?: React.ReactNode
}

/**
 * The footer of a list drawn as cards (below 768px): instead of the numbered
 * pager, one full-width "Show 25 more" button and a line "50 of 418". The
 * button grows the page size by one step, so the cards already on screen stay
 * where they are, the new ones come under them and the first new card takes
 * the focus. The page size is the list's own (`per_page` in its URL), so a
 * reload shows the same number of cards. At the largest page size the API
 * returns, the button gives way to a line that says how to see the rest.
 */
export function PhoneMoreFooter({
  shown,
  total,
  pageIndex,
  pageSize,
  mayHaveMore = true,
  maxPageSize,
  onPageSizeChange,
  onFirstPage,
  busy = false,
  cardsRef,
  note,
}: PhoneMoreFooterProps) {
  const { t } = useTranslation()

  const onFirstPageRef = React.useRef(onFirstPage)
  React.useLayoutEffect(() => {
    onFirstPageRef.current = onFirstPage
  })
  React.useEffect(() => {
    if (pageIndex > 0) onFirstPageRef.current()
  }, [pageIndex])

  // The card count when "Show more" was pressed: the first card past it is
  // the first new one.
  const grewFrom = React.useRef<number | null>(null)
  React.useEffect(() => {
    const from = grewFrom.current
    if (from === null || shown === from) return
    grewFrom.current = null
    if (shown < from) return
    const card = cardsRef.current?.querySelectorAll<HTMLElement>(PHONE_CARD_SELECTOR)[from]
    // The new card is where the button was: the page must not scroll to it.
    card?.focus({ preventScroll: true })
  }, [shown, cardsRef])

  // Without a total, a full page is the only sign that more rows follow.
  const hasMore = total !== undefined ? shown < total : mayHaveMore && shown >= pageSize
  const next = hasMore ? nextPhonePageSize(pageSize, maxPageSize) : null
  const step =
    next === null
      ? 0
      : total !== undefined
        ? Math.min(next - shown, total - shown)
        : next - Math.min(shown, pageSize)

  return (
    <div data-slot="phone-more-footer" className="flex flex-col items-stretch gap-2">
      {next !== null && step > 0 && (
        <Button
          variant="outline"
          data-slot="phone-show-more"
          className="w-full"
          disabled={busy}
          onClick={() => {
            grewFrom.current = shown
            onPageSizeChange(next)
          }}
        >
          {t('common.table.showMore', 'Show {count} more', { count: formatNumber(step) })}
        </Button>
      )}
      <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 text-center text-cap text-muted-foreground tabular-nums">
        {note}
        <span data-slot="phone-shown-count">
          {total !== undefined
            ? t('common.table.shownOfTotal', '{shown} of {total}', {
                shown: formatNumber(shown),
                total: formatNumber(total),
              })
            : t('common.table.shownCount', '{shown} shown', { shown: formatNumber(shown) })}
        </span>
        {hasMore && next === null && maxPageSize !== undefined && (
          <span data-slot="phone-more-cap" className="basis-full">
            {t(
              'common.table.showMoreCap',
              'These are the first {max}. Narrow the filters to see the rest.',
              { max: formatNumber(maxPageSize) }
            )}
          </span>
        )}
      </div>
    </div>
  )
}
