'use client'

import { useEffect, useLayoutEffect, useRef, type ReactNode, type RefObject } from 'react'
import { ChevronDown, MoreHorizontal, X } from 'lucide-react'
import { ActionMenu, type ActionMenuEntry } from '@/components/ui/action-menu'
import { Button } from '@/components/ui/button'
import { DensityScope } from '@/components/ui/density'
import { useFloatingObstruction } from '@/components/ui/floating'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { useTranslation } from '@/context/i18n-provider'

/** The CSS property that holds the room the bar takes at the bottom of the screen. */
export const BULK_BAR_SPACE_VAR = '--bulk-bar-space'

/** Open popups whose own Escape must not clear the selection as well. */
const POPUP_SELECTOR = '[role="menu"], [role="dialog"], [role="alertdialog"], [role="listbox"]'

/** The gap kept between the last row of the page and the bar. */
const BAR_GAP = 16

/**
 * Actions for the rows selected in a list, as a bar floating at the bottom of
 * the viewport. It appears over the content instead of being inserted above
 * the table, so selecting a row never shifts the list. Escape clears the
 * selection. While it shows, the page keeps room for it under its last row
 * (`--bulk-bar-space`, read by `Main`), so it never covers the last card or
 * the pager.
 *
 * Anatomy: the count, an optional status ("Select all N that match" or "All N
 * that match are selected"), a divider, at most two direct actions, More
 * (the rest, as menu items) and X. Every control is one height: the kit's
 * dense size (28) on a desktop. Below 768px it is a full-width bottom row of
 * two lines (the count and X, then the actions), every control 36; with
 * `selectMenu` the count is a menu (select the page, select all that match,
 * clear), since a phone card list has no header checkbox.
 */
/** The words after the selection count, given the count (plural forms in the catalog). */
export type BulkNoun = string | ((count: number) => string)

export function BulkActionBar({
  count,
  onClear,
  children,
  noun,
  status,
  more,
  open = false,
  selectMenu,
}: {
  count: number
  onClear: () => void
  /** At most two direct actions. */
  children: ReactNode
  /**
   * Text after the count, e.g. "findings selected": a function of the count,
   * so the catalog string picks its plural form (`{count, plural, ...}`).
   */
  noun?: BulkNoun
  /** Beside the count: the select-all-matching offer or its state. */
  status?: ReactNode
  /** The other actions, under More (the shared `ActionMenu`). */
  more?: ActionMenuEntry[]
  /**
   * Keep the bar while nothing is selected (a phone list in select mode); the
   * actions are disabled until a row is selected.
   */
  open?: boolean
  /**
   * Below 768px the count opens these `DropdownMenuItem`s (select the page,
   * select all that match, clear); `status` then stays off the phone bar.
   */
  selectMenu?: ReactNode
}) {
  const { t } = useTranslation()
  const shown = count > 0 || open
  const barRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!shown) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape' || e.defaultPrevented) return
      // Escape in an open menu or dialog closes that, not the selection.
      const target = e.target instanceof Element ? e.target : null
      if (target?.closest(POPUP_SELECTOR)) return
      onClear()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [shown, onClear])
  useBarSpace(barRef, shown)
  // Menus and popovers keep clear of the bar while it shows.
  useFloatingObstruction(barRef, shown)

  if (!shown) return null
  const nounText = typeof noun === 'function' ? noun(count) : noun
  const countText = (
    <>
      {count.toLocaleString()}{' '}
      {nounText ? (
        // A phone shows the short word only, so X stays on screen; screen
        // readers hear the page's noun at every width.
        <>
          <span className="sr-only sm:not-sr-only">{nounText}</span>
          <span aria-hidden="true" className="sm:hidden">
            {t('common.bulkBar.selected', 'selected')}
          </span>
        </>
      ) : (
        t('common.bulkBar.selected', 'selected')
      )}
    </>
  )
  return (
    <div className="pointer-events-none fixed inset-x-0 bottom-6 z-40 flex justify-center px-4 max-md:bottom-[calc(0.5rem+env(safe-area-inset-bottom))] max-md:px-2">
      <div
        ref={barRef}
        role="toolbar"
        aria-label={t('common.bulkBar.label', 'Actions for selected rows')}
        data-slot="bulk-action-bar"
        className="pointer-events-auto flex max-w-full animate-in items-center gap-1.5 overflow-x-auto rounded-xl border bg-popover p-1.5 ps-4 text-popover-foreground shadow-lg duration-200 fade-in-0 slide-in-from-bottom-2 max-md:w-full max-md:flex-wrap max-md:gap-2 max-md:overflow-visible max-md:p-2"
      >
        <span
          className={
            selectMenu
              ? 'whitespace-nowrap text-sm font-medium tabular-nums max-md:hidden'
              : 'whitespace-nowrap text-sm font-medium tabular-nums max-md:me-auto max-md:ps-2'
          }
        >
          {countText}
        </span>
        {/* Dense on a desktop; a phone keeps every control at 36. */}
        <DensityScope touch="default">
          {selectMenu && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="ghost"
                  size="sm"
                  data-slot="bulk-bar-select-menu"
                  className="me-auto md:hidden"
                  aria-label={t(
                    'common.bulkBar.selectMenu',
                    '{count} selected: selection options',
                    {
                      count: count.toLocaleString(),
                    }
                  )}
                >
                  <span className="text-sm font-medium tabular-nums">{countText}</span>
                  <ChevronDown aria-hidden className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent side="top">{selectMenu}</DropdownMenuContent>
            </DropdownMenu>
          )}
          {status && (
            <span className={selectMenu ? 'contents max-md:hidden' : 'contents'}>{status}</span>
          )}
          <span aria-hidden className="mx-1.5 h-5 w-px shrink-0 bg-border max-md:hidden" />
          {/* Phone: X ends the first line, the actions take the second. */}
          <Button
            variant="ghost"
            size="icon-sm"
            className="shrink-0 md:order-last"
            onClick={onClear}
            aria-label={t('common.bulkBar.clear', 'Clear selection')}
            title={t('common.bulkBar.clearHint', 'Clear selection (Esc)')}
          >
            <X className="h-4 w-4" />
          </Button>
          <fieldset
            disabled={count === 0}
            data-slot="bulk-bar-actions"
            className="contents max-md:flex max-md:min-w-0 max-md:basis-full max-md:items-center max-md:gap-2"
          >
            {children}
            {more && more.length > 0 && (
              <ActionMenu
                items={more}
                title={`${count.toLocaleString()} ${nounText ?? t('common.bulkBar.selected', 'selected')}`}
                label={t('common.bulkBar.label', 'Actions for selected rows')}
                trigger={
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    className="shrink-0 max-md:ms-auto"
                    aria-label={t('common.bulkBar.more', 'More actions')}
                  >
                    <MoreHorizontal className="h-4 w-4" aria-hidden />
                  </Button>
                }
              />
            )}
          </fieldset>
        </DensityScope>
      </div>
    </div>
  )
}

/**
 * While the bar shows, `--bulk-bar-space` on the document root holds the room
 * it takes from the bottom of the screen plus a gap; `Main` adds it to its
 * bottom padding, so the last row scrolls clear of the bar.
 */
function useBarSpace(barRef: RefObject<HTMLDivElement | null>, shown: boolean) {
  useLayoutEffect(() => {
    const bar = barRef.current
    if (!shown || !bar) return
    const root = document.documentElement
    const measure = () => {
      const top = bar.getBoundingClientRect().top
      const space = Math.max(0, Math.ceil(window.innerHeight - top)) + BAR_GAP
      root.style.setProperty(BULK_BAR_SPACE_VAR, `${space}px`)
    }
    measure()
    const ro = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(measure)
    ro?.observe(bar)
    window.addEventListener('resize', measure)
    // The bar slides in: measure again where it comes to rest.
    bar.addEventListener('animationend', measure)
    return () => {
      ro?.disconnect()
      window.removeEventListener('resize', measure)
      bar.removeEventListener('animationend', measure)
      root.style.removeProperty(BULK_BAR_SPACE_VAR)
    }
  }, [barRef, shown])
}
