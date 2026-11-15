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
import { focusSurface, opensWithTextFocus } from '@/components/ui/touch-focus'
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
 * - nearly full height while the keyboard is down; once the user taps the
 *   field and the keyboard opens, it sits on the keyboard and is never taller
 *   than the visible part of the screen (`--modal-kb` and `--modal-vvh`, set
 *   from `visualViewport`), so the field and the rows under it stay in view
 *   even when the browser pans the page;
 * - the title in a fixed header, the content's search field pinned under it
 *   (sticky) while the list scrolls in the sheet body under sticky group
 *   headings; a `Command`'s list loses its 300px cap; rows are 44px;
 * - on a touch screen opening it does not focus the field (no keyboard until
 *   the user taps it): the option list takes focus, its first option active;
 *   with a mouse the field gets focus, so typing starts at once
 *   (`touch-focus.ts`);
 * - focus moves into the sheet and returns to the trigger on close (Radix
 *   Dialog), the field is blurred on close so the keyboard goes with the
 *   sheet; Escape and the close button close it.
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
  /** Popover alignment from `md` up; by default the kit's (by the trigger's half of the screen). */
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
  align,
  className,
}: ResponsivePopoverProps) {
  const isMobile = useIsMobile()

  const handleOpenChange = React.useCallback(
    (next: boolean) => {
      // The keyboard closes with the sheet, not after the focus has moved on.
      if (!next) {
        const active = document.activeElement
        if (
          active instanceof HTMLElement &&
          active.closest('[data-slot="responsive-popover-sheet"]')
        )
          active.blur()
      }
      onOpenChange(next)
    },
    [onOpenChange]
  )

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
    <Sheet open={open} onOpenChange={handleOpenChange}>
      <SheetTrigger asChild>{trigger}</SheetTrigger>
      <SheetContent
        side="bottom"
        data-slot="responsive-popover-sheet"
        // Keyboard down: the screen less the top inset and a 40px strip of
        // page. Keyboard up: also never taller than the visible part less 8px,
        // so its top (the field) stays on screen when the browser pans.
        className="h-[min(calc(100dvh_-_var(--modal-kb,0px)_-_env(safe-area-inset-top)_-_2.5rem),calc(var(--modal-vvh,100dvh)_-_0.5rem))] rounded-t-xl"
        onOpenAutoFocus={(e) => {
          const sheet = e.currentTarget as HTMLElement | null
          const field = sheet?.querySelector<HTMLElement>(
            '[data-slot="command-input"], input[type="search"]'
          )
          if (!sheet || !field) return
          e.preventDefault()
          // With a mouse straight into the search field; on a touch screen
          // the list, so the keyboard waits for a tap on the field.
          if (opensWithTextFocus()) field.focus()
          else focusSurface(sheet)
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
            // Group headings stick under the field while their rows scroll.
            '[&_[data-slot=command-group]]:overflow-visible [&_[cmdk-group-heading]]:sticky [&_[cmdk-group-heading]]:top-12 [&_[cmdk-group-heading]]:z-[5] [&_[cmdk-group-heading]]:bg-background',
            // Rows sized for a finger.
            '[&_[data-slot=command-item]]:min-h-11',
            // Clear of the home indicator while the keyboard is down; 16px on
            // the keyboard (the inset is then negative).
            'pb-[max(1rem,calc(env(safe-area-inset-bottom)_-_var(--modal-kb,0px)))]'
          )}
        >
          {children}
        </SheetBody>
      </SheetContent>
    </Sheet>
  )
}
