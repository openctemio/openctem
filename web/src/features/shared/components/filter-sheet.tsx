'use client'

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
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="left" className="w-full" data-slot="filter-sheet">
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
        </SheetHeader>
        <SheetBody>{children}</SheetBody>
        <SheetFooter>
          <Button className="w-full" onClick={() => onOpenChange(false)}>
            {resultLabel ?? t('common.filterSheet.showResults', 'Show results')}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}
