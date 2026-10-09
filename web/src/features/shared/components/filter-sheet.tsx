'use client'

import type { ReactNode } from 'react'
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
  resultLabel = 'Show results',
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
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="left" className="w-full" data-slot="filter-sheet">
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
        </SheetHeader>
        <SheetBody>{children}</SheetBody>
        <SheetFooter>
          <Button className="w-full" onClick={() => onOpenChange(false)}>
            {resultLabel}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}
