'use client'

import * as React from 'react'

import { Drawer, DrawerContent, DrawerHandle } from '@/components/ui/drawer'
import { cn } from '@/lib/utils'

/**
 * Inputs and other controls never start a drag: dragging on a text field
 * selects text or moves the caret, a slider slides. Vaul skips any element
 * under `[data-vaul-no-drag]`, so the control under the finger is tagged as
 * the press starts, before Vaul decides.
 */
const NO_DRAG_SELECTOR =
  'input, textarea, select, [contenteditable=""], [contenteditable="true"], [role="slider"], [role="textbox"]'

function keepControlsFromDragging(e: React.PointerEvent) {
  const target = e.target
  if (!(target instanceof Element)) return
  const control = target.closest(NO_DRAG_SELECTOR)
  if (control && !control.hasAttribute('data-vaul-no-drag')) {
    control.setAttribute('data-vaul-no-drag', '')
  }
}

/**
 * The phone form of the detail sheet: a bottom sheet on Vaul that follows the
 * finger. Loaded on demand by detail-sheet-layout.tsx.
 */
export function PhoneDrawer({
  open,
  onOpenChange,
  className,
  onOpenAutoFocus,
  onCloseAutoFocus,
  children,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  className?: string
  onOpenAutoFocus: (e: Event) => void
  onCloseAutoFocus: (e: Event) => void
  children: React.ReactNode
}) {
  return (
    <Drawer open={open} onOpenChange={onOpenChange}>
      <DrawerContent
        data-slot="detail-sheet"
        className={cn(
          'w-full gap-0 overflow-hidden supports-[overflow:clip]:overflow-clip p-0 outline-none',
          'rounded-t-2xl border-t pb-[env(safe-area-inset-bottom)]',
          className
        )}
        onPointerDownCapture={keepControlsFromDragging}
        onOpenAutoFocus={onOpenAutoFocus}
        onCloseAutoFocus={onCloseAutoFocus}
      >
        <DrawerHandle />
        {children}
      </DrawerContent>
    </Drawer>
  )
}
