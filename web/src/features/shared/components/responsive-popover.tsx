'use client'

import * as React from 'react'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  Sheet,
  SheetBody,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet'
import { useIsMobile } from '@/hooks/use-mobile'
import { cn } from '@/lib/utils'

/**
 * A toolbar popover that holds a text field (Add filter, a value picker).
 *
 * From `md` up it is the anchored popover. On a phone an anchored popover
 * breaks as soon as the on-screen keyboard opens: the popover is pushed under
 * the status bar, its search field leaves the screen and the page shows
 * beside it. Below `md` the same content opens as a bottom sheet instead:
 *
 * - nearly full height, sized by `100dvh` minus the keyboard (the sheet's
 *   `--modal-kb`, set from `visualViewport`), so the keyboard never covers
 *   the field or the list;
 * - the title in a fixed header, the content's search field pinned under it
 *   (sticky) while the list scrolls in the sheet body; a `Command`'s list
 *   loses its 300px cap; the field gets focus when the sheet opens;
 * - focus moves into the sheet and returns to the trigger on close (Radix
 *   Dialog), Escape and the close button close it.
 *
 * The content is the same element in both forms; it never needs to know
 * which one it is in.
 */
export interface ResponsivePopoverProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The trigger button (rendered `asChild`). */
  trigger: React.ReactElement
  /** Accessible name; also the sheet title on a phone. */
  title: string
  children: React.ReactNode
  /** Popover alignment from `md` up. */
  align?: 'start' | 'center' | 'end'
  /** Classes of the desktop popover (its width). */
  className?: string
}

export function ResponsivePopover({
  open,
  onOpenChange,
  trigger,
  title,
  children,
  align = 'start',
  className,
}: ResponsivePopoverProps) {
  const isMobile = useIsMobile()

  if (!isMobile) {
    return (
      <Popover open={open} onOpenChange={onOpenChange}>
        <PopoverTrigger asChild>{trigger}</PopoverTrigger>
        <PopoverContent align={align} className={cn('p-0', className)} aria-label={title}>
          {children}
        </PopoverContent>
      </Popover>
    )
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetTrigger asChild>{trigger}</SheetTrigger>
      <SheetContent
        side="bottom"
        data-slot="responsive-popover-sheet"
        className="h-[calc(100dvh-var(--modal-kb,0px)-env(safe-area-inset-top)-2.5rem)] rounded-t-xl"
        onOpenAutoFocus={(e) => {
          // Straight into the search field, so typing starts at once.
          const field = (e.currentTarget as HTMLElement | null)?.querySelector<HTMLElement>(
            '[data-slot="command-input"], input[type="search"]'
          )
          if (field) {
            e.preventDefault()
            field.focus()
          }
        }}
      >
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
        </SheetHeader>
        <SheetBody
          data-testid="responsive-popover-body"
          className={cn(
            'p-0',
            // The search field stays pinned under the title while the list
            // scrolls; the list loses its desktop height cap.
            '[&_[data-slot=command-input-wrapper]]:sticky [&_[data-slot=command-input-wrapper]]:top-0 [&_[data-slot=command-input-wrapper]]:z-10 [&_[data-slot=command-input-wrapper]]:h-12 [&_[data-slot=command-input-wrapper]]:bg-background',
            '[&_[data-slot=command]]:h-auto [&_[data-slot=command]]:overflow-visible [&_[data-slot=command-list]]:max-h-none [&_[data-slot=command-list]]:overflow-visible',
            // Rows sized for a finger.
            '[&_[data-slot=command-item]]:min-h-11'
          )}
        >
          {children}
        </SheetBody>
      </SheetContent>
    </Sheet>
  )
}
