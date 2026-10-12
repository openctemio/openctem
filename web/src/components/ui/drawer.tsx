'use client'

/**
 * shadcn/ui Drawer: a bottom sheet you can swipe down to close, on Vaul
 * (https://vaul.emilkowal.ski), which is Radix Dialog underneath (focus trap,
 * Esc, return focus, title and description as for `Dialog` and `Sheet`).
 *
 * Vaul animates with its own transform keyframes and inline transforms while
 * dragging, so the overlay and content here carry no `animate-in` classes.
 */

import * as React from 'react'
import { Drawer as DrawerPrimitive } from 'vaul'

import { ignoreToasterInteractions } from '@/components/ui/toaster-guard'
import { cn } from '@/lib/utils'

function Drawer({ ...props }: React.ComponentProps<typeof DrawerPrimitive.Root>) {
  return <DrawerPrimitive.Root data-slot="drawer" {...props} />
}

function DrawerTrigger({ ...props }: React.ComponentProps<typeof DrawerPrimitive.Trigger>) {
  return <DrawerPrimitive.Trigger data-slot="drawer-trigger" {...props} />
}

function DrawerPortal({ ...props }: React.ComponentProps<typeof DrawerPrimitive.Portal>) {
  return <DrawerPrimitive.Portal data-slot="drawer-portal" {...props} />
}

function DrawerClose({ ...props }: React.ComponentProps<typeof DrawerPrimitive.Close>) {
  return <DrawerPrimitive.Close data-slot="drawer-close" {...props} />
}

function DrawerOverlay({
  className,
  ...props
}: React.ComponentProps<typeof DrawerPrimitive.Overlay>) {
  return (
    <DrawerPrimitive.Overlay
      data-slot="drawer-overlay"
      // No backdrop blur: a blur under a moving sheet is re-rasterised every
      // frame, the most expensive thing a phone GPU can be asked to animate.
      className={cn('fixed inset-0 z-50 bg-black/50', className)}
      {...props}
    />
  )
}

function DrawerContent({
  className,
  children,
  onInteractOutside,
  ...props
}: React.ComponentProps<typeof DrawerPrimitive.Content>) {
  return (
    <DrawerPortal>
      <DrawerOverlay />
      <DrawerPrimitive.Content
        data-slot="drawer-content"
        className={cn(
          'group/drawer-content fixed z-50 flex h-auto flex-col bg-background',
          'data-[vaul-drawer-direction=bottom]:inset-x-0 data-[vaul-drawer-direction=bottom]:bottom-0 data-[vaul-drawer-direction=bottom]:max-h-[92svh] data-[vaul-drawer-direction=bottom]:rounded-t-2xl data-[vaul-drawer-direction=bottom]:border-t',
          'data-[vaul-drawer-direction=top]:inset-x-0 data-[vaul-drawer-direction=top]:top-0 data-[vaul-drawer-direction=top]:max-h-[92svh] data-[vaul-drawer-direction=top]:rounded-b-2xl data-[vaul-drawer-direction=top]:border-b',
          className
        )}
        onInteractOutside={ignoreToasterInteractions(onInteractOutside)}
        {...props}
      >
        {children}
      </DrawerPrimitive.Content>
    </DrawerPortal>
  )
}

/**
 * The grabber: a short bar with a 44x44 hit area (Vaul's), in a full-width
 * strip that, like the header under it, starts a drag. Decorative for assistive technology (the sheet has a Close button);
 * swiping is never the only way to close.
 */
function DrawerHandle({
  className,
  ...props
}: React.ComponentProps<typeof DrawerPrimitive.Handle>) {
  return (
    <div
      data-slot="drawer-handle-area"
      className="flex h-5 w-full shrink-0 items-center justify-center"
    >
      <DrawerPrimitive.Handle
        data-slot="drawer-handle"
        // Vaul's own handle styles are attribute selectors injected at
        // runtime; `!` keeps the theme's colour and size.
        className={cn('h-1! w-9! bg-border! opacity-100!', className)}
        {...props}
      />
    </div>
  )
}

function DrawerHeader({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="drawer-header"
      className={cn('flex flex-col gap-1.5 p-4 text-center sm:text-left', className)}
      {...props}
    />
  )
}

function DrawerFooter({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="drawer-footer"
      className={cn('mt-auto flex flex-col gap-2 p-4', className)}
      {...props}
    />
  )
}

function DrawerTitle({ className, ...props }: React.ComponentProps<typeof DrawerPrimitive.Title>) {
  return (
    <DrawerPrimitive.Title
      data-slot="drawer-title"
      className={cn('font-semibold text-foreground', className)}
      {...props}
    />
  )
}

function DrawerDescription({
  className,
  ...props
}: React.ComponentProps<typeof DrawerPrimitive.Description>) {
  return (
    <DrawerPrimitive.Description
      data-slot="drawer-description"
      className={cn('text-sm text-muted-foreground', className)}
      {...props}
    />
  )
}

export {
  Drawer,
  DrawerPortal,
  DrawerOverlay,
  DrawerTrigger,
  DrawerClose,
  DrawerContent,
  DrawerHandle,
  DrawerHeader,
  DrawerFooter,
  DrawerTitle,
  DrawerDescription,
}
