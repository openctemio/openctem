'use client'

import * as React from 'react'
import type { ReactNode } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Button } from '@/components/ui/button'
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'

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

/**
 * The filter panel below `lg`, opened by `FilterPanelToggle`'s sheet button.
 * One markup for every list page (it was the Findings sheet): full width on a
 * phone, the title and close button in the fixed header, the facet list
 * scrolling between it and a footer that closes the sheet.
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
  // The host leaves with the sheet, and so does the claim on it.
  const hostRef = React.useCallback((el: HTMLDivElement | null) => {
    setTokensHost(el ? { host: el } : { host: null, owner: null })
  }, [])
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="left" className="w-full" data-slot="filter-sheet">
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
        </SheetHeader>
        <SheetBody>
          {/* The list toolbar's filter tokens, on a phone (see above). */}
          <div
            ref={hostRef}
            data-slot="filter-sheet-tokens"
            className="mb-4 flex flex-wrap items-center gap-2 border-b pb-4 empty:hidden"
          />
          {children}
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
