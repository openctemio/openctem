'use client'

import * as React from 'react'
import * as PopoverPrimitive from '@radix-ui/react-popover'

import { cn } from '@/lib/utils'
import {
  FLOATING_COLLISION_PADDING,
  FLOATING_SURFACE_CLASSES,
  FloatingAnchorProvider,
  useFloatingContent,
  useFloatingRoot,
  useFloatingAnchorSetter,
} from '@/components/ui/floating'
import {
  FloatingFocusScope,
  redirectOpenFocus,
  type TouchTypingSurface,
} from '@/components/ui/touch-focus'

function Popover(props: React.ComponentProps<typeof PopoverPrimitive.Root>) {
  const { state, onOpenChange } = useFloatingRoot(props)
  return (
    <FloatingAnchorProvider state={state}>
      <PopoverPrimitive.Root data-slot="popover" {...props} onOpenChange={onOpenChange} />
    </FloatingAnchorProvider>
  )
}

function PopoverTrigger({ ref, ...props }: React.ComponentProps<typeof PopoverPrimitive.Trigger>) {
  const record = useFloatingAnchorSetter()
  const triggerRef = React.useCallback(
    (node: HTMLButtonElement | null) => {
      if (typeof ref === 'function') ref(node)
      else if (ref) ref.current = node
      record(node)
    },
    [ref, record]
  )
  return <PopoverPrimitive.Trigger data-slot="popover-trigger" ref={triggerRef} {...props} />
}

/**
 * Anchored panel. Lines up with the start or end edge of its trigger by the
 * half of the screen the trigger is in (unless `align` says), is never taller
 * than the room on its side (it scrolls inside, with a cue) and never
 * narrower than its trigger. On a touch screen it opens without focusing a
 * text field (`touch-focus.ts`), unless it is a `typingSurface`.
 */
function PopoverContent({
  className,
  align,
  side,
  sideOffset = 4,
  collisionPadding = FLOATING_COLLISION_PADDING,
  style,
  onOpenAutoFocus,
  typingSurface,
  children,
  ...props
}: React.ComponentProps<typeof PopoverPrimitive.Content> & {
  /** Its one purpose is typing: the field gets focus on open on a touch screen too. */
  typingSurface?: TouchTypingSurface
}) {
  const floating = useFloatingContent({ align, side, collisionPadding, fallbackAlign: 'start' })
  const handleOpenAutoFocus = React.useCallback(
    (event: Event) => {
      onOpenAutoFocus?.(event)
      redirectOpenFocus(event, event.currentTarget as HTMLElement | null, typingSurface)
    },
    [onOpenAutoFocus, typingSurface]
  )
  return (
    <PopoverPrimitive.Portal>
      <PopoverPrimitive.Content
        data-slot="popover-content"
        side={side}
        align={floating.align}
        sideOffset={sideOffset}
        collisionPadding={floating.collisionPadding}
        style={{ ...floating.style, ...style }}
        onOpenAutoFocus={handleOpenAutoFocus}
        className={cn(
          FLOATING_SURFACE_CLASSES,
          'scroll-cue bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 z-50 max-h-(--radix-popover-content-available-height) w-72 min-w-(--radix-popover-trigger-width) origin-(--radix-popover-content-transform-origin) overflow-y-auto rounded-md border p-4 shadow-md outline-hidden',
          className
        )}
        {...props}
      >
        {props.asChild ? (
          // The Slot needs the caller's element as its only child.
          children
        ) : (
          <FloatingFocusScope typingSurface={typingSurface}>{children}</FloatingFocusScope>
        )}
      </PopoverPrimitive.Content>
    </PopoverPrimitive.Portal>
  )
}

function PopoverAnchor({ ref, ...props }: React.ComponentProps<typeof PopoverPrimitive.Anchor>) {
  const record = useFloatingAnchorSetter('anchor')
  const anchorRef = React.useCallback(
    (node: HTMLDivElement | null) => {
      if (typeof ref === 'function') ref(node)
      else if (ref) ref.current = node
      record(node)
    },
    [ref, record]
  )
  return <PopoverPrimitive.Anchor data-slot="popover-anchor" ref={anchorRef} {...props} />
}

export { Popover, PopoverTrigger, PopoverContent, PopoverAnchor }
