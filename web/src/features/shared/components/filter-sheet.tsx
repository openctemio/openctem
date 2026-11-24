'use client'

import * as React from 'react'
import type { ReactNode } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { useIsMobile } from '@/hooks/use-mobile'
import { Button } from '@/components/ui/button'
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { drawsSomething } from './draws-something'

/**
 * On a phone a list toolbar's filter tokens (`ListToolbar` `start`) are not
 * drawn in the toolbar: they show at the top of the list's filter sheet. The
 * sheet offers a host for them; the toolbar whose Filters button opened the
 * sheet claims it (one sheet is open at a time) and renders its tokens there.
 */
type TokensHost = { owner: string | null; host: HTMLElement | null }
let tokensHost: TokensHost = { owner: null, host: null }
const tokensListeners = new Set<() => void>()
function setTokensHost(next: Partial<TokensHost>) {
  tokensHost = { ...tokensHost, ...next }
  tokensListeners.forEach((l) => l())
}
function subscribeTokensHost(l: () => void) {
  tokensListeners.add(l)
  return () => {
    tokensListeners.delete(l)
  }
}
const readTokensHost = () => tokensHost

/** The toolbar `owner` opens the sheet: its tokens show in it. */
export function claimFilterSheetTokens(owner: string) {
  setTokensHost({ owner })
}

/** Where the toolbar `owner` renders its tokens while its sheet is open, else null. */
export function useFilterSheetTokensHost(owner: string): HTMLElement | null {
  const s = React.useSyncExternalStore(subscribeTokensHost, readTokensHost, readTokensHost)
  return s.owner === owner ? s.host : null
}

/** The facet panel's "Clear all", lent to the sheet's header. */
type SheetClearAll = { activeCount: number; onClearAll: () => void }

/**
 * Inside a `FilterSheet`, a `FacetPanel` draws no heading of its own (the
 * sheet's title already names the filters) and hands its "Clear all" to the
 * sheet, which shows it beside the title.
 */
const FilterSheetContext = React.createContext<((clear: SheetClearAll | null) => void) | null>(null)

/** The setter for the sheet's Clear all, or null outside a `FilterSheet`. */
export function useFilterSheetClearAll() {
  return React.useContext(FilterSheetContext)
}

/**
 * Selects in the sheet take the whole width (a token sized for the toolbar
 * stopped at half the sheet on a phone), with the value at the start and the
 * chevron at the end.
 */
const SHEET_FIELDS_CLASS =
  '[&_[data-slot=filter-select]]:flex [&_[data-slot=filter-select]]:w-full [&_[data-slot=filter-select]>button]:flex-1 [&_[data-slot=filter-select]>button>svg:last-child]:ms-auto'

/**
 * The filter panel below `lg`, opened by `FilterPanelToggle`'s sheet button.
 * One markup for every list page (it was the Findings sheet): the title, Clear
 * all and the close button in the fixed header, the facet list scrolling
 * between it and a footer that closes the sheet.
 *
 * On a phone it is a bottom sheet as tall as what it holds (two filters take
 * two rows, not the whole screen), up to the screen less a strip of page at
 * the top; longer content scrolls in the body. From `md` it is the side panel
 * the whole height of the window, where the facet lists are long.
 */
export function FilterSheet({
  open,
  onOpenChange,
  title,
  resultLabel,
  children,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Title of the sheet, e.g. "Finding filters". */
  title: string
  /** Footer button text, e.g. "Show 12 findings". */
  resultLabel?: string
  /** A `FacetPanel`. */
  children: ReactNode
}) {
  const { t } = useTranslation()
  const phone = useIsMobile()
  const [clearAll, setClearAll] = React.useState<SheetClearAll | null>(null)
  // The host leaves with the sheet, and so does the claim on it.
  const hostElRef = React.useRef<HTMLDivElement | null>(null)
  const hostRef = React.useCallback((el: HTMLDivElement | null) => {
    hostElRef.current = el
    setTokensHost(el ? { host: el } : { host: null, owner: null })
  }, [])
  // The tokens' band (with its divider) is drawn only while a token draws
  // something: a token that renders an empty box left a blank band and a
  // divider under the title.
  React.useLayoutEffect(() => {
    if (!open) return
    let frame = 0
    let observer: MutationObserver | null = null
    const mark = () => {
      const el = hostElRef.current
      if (!el) return
      el.removeAttribute('data-empty')
      const empty = !drawsSomething(el)
      el.toggleAttribute('data-empty', empty)
    }
    // The sheet's content mounts in a portal after this effect: wait a frame.
    frame = requestAnimationFrame(() => {
      mark()
      const el = hostElRef.current
      if (!el || typeof MutationObserver === 'undefined') return
      observer = new MutationObserver(mark)
      observer.observe(el, { subtree: true, childList: true })
    })
    return () => {
      cancelAnimationFrame(frame)
      observer?.disconnect()
    }
  }, [open])
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side={phone ? 'bottom' : 'left'}
        className={phone ? undefined : 'w-full'}
        data-slot="filter-sheet"
      >
        <SheetHeader
          actions={
            clearAll ? (
              <Button
                variant="ghost"
                size="sm"
                data-slot="filter-sheet-clear-all"
                onClick={clearAll.onClearAll}
                disabled={clearAll.activeCount === 0}
              >
                {t('common.clearAll', 'Clear all')}
              </Button>
            ) : undefined
          }
        >
          <SheetTitle>{title}</SheetTitle>
        </SheetHeader>
        <SheetBody className={SHEET_FIELDS_CLASS}>
          {/* The list toolbar's filter tokens, on a phone (see above). */}
          <div
            ref={hostRef}
            data-slot="filter-sheet-tokens"
            className="mb-4 flex flex-col items-stretch gap-2 border-b pb-4 empty:hidden data-[empty]:hidden"
          />
          <FilterSheetContext.Provider value={setClearAll}>{children}</FilterSheetContext.Provider>
        </SheetBody>
        <SheetFooter>
          <Button className="w-full" onClick={() => onOpenChange(false)}>
            {resultLabel ?? t('common.filterSheet.showResults', 'Show results')}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}
