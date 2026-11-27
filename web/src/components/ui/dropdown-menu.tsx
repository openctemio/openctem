'use client'

import * as React from 'react'
import * as DropdownMenuPrimitive from '@radix-ui/react-dropdown-menu'
import { CheckIcon, ChevronRightIcon, CircleIcon } from 'lucide-react'

import { cn } from '@/lib/utils'
import {
  FLOATING_COLLISION_PADDING,
  FLOATING_SURFACE_CLASSES,
  FloatingAnchorProvider,
  useFloatingContent,
  useFloatingRoot,
  useFloatingAnchorSetter,
} from '@/components/ui/floating'

function DropdownMenu(props: React.ComponentProps<typeof DropdownMenuPrimitive.Root>) {
  const { state, onOpenChange } = useFloatingRoot(props)
  return (
    <FloatingAnchorProvider state={state}>
      <DropdownMenuPrimitive.Root
        data-slot="dropdown-menu"
        {...props}
        onOpenChange={onOpenChange}
      />
    </FloatingAnchorProvider>
  )
}

function DropdownMenuPortal({
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.Portal>) {
  return <DropdownMenuPrimitive.Portal data-slot="dropdown-menu-portal" {...props} />
}

function DropdownMenuTrigger({
  ref,
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.Trigger>) {
  const record = useFloatingAnchorSetter()
  const triggerRef = React.useCallback(
    (node: HTMLButtonElement | null) => {
      if (typeof ref === 'function') ref(node)
      else if (ref) ref.current = node
      record(node)
    },
    [ref, record]
  )
  return (
    <DropdownMenuPrimitive.Trigger data-slot="dropdown-menu-trigger" ref={triggerRef} {...props} />
  )
}

/**
 * Width of a menu and its submenus (`FLOATING_MENU_*` in floating.ts): the
 * content's own, at least the trigger's width or 128 px (160 px with icons),
 * at most 360 px or the screen less its gutters. After FLOATING_SURFACE_CLASSES.
 */
const MENU_WIDTH =
  'max-w-[min(22.5rem,calc(100vw_-_var(--float-gutter-x,2rem)))] min-w-[max(8rem,var(--radix-dropdown-menu-trigger-width,0px))] has-[svg]:min-w-[max(10rem,var(--radix-dropdown-menu-trigger-width,0px))]'
const SUBMENU_WIDTH =
  'max-w-[min(22.5rem,calc(100vw_-_var(--float-gutter-x,2rem)))] min-w-[8rem] has-[svg]:min-w-[10rem]'

function DropdownMenuContent({
  className,
  sideOffset = 4,
  align,
  side,
  collisionPadding = FLOATING_COLLISION_PADDING,
  style,
  ref,
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.Content>) {
  const floating = useFloatingContent({
    align,
    side,
    collisionPadding,
    fallbackAlign: 'start',
  })
  const { attach } = floating
  const contentRef = React.useCallback(
    (node: HTMLDivElement | null) => {
      attach(node)
      if (typeof ref === 'function') ref(node)
      else if (ref) ref.current = node
    },
    [ref, attach]
  )
  return (
    <DropdownMenuPrimitive.Portal>
      <DropdownMenuPrimitive.Content
        ref={contentRef}
        data-slot="dropdown-menu-content"
        sideOffset={sideOffset}
        side={side}
        align={floating.align}
        collisionPadding={floating.collisionPadding}
        style={{ ...floating.style, ...style }}
        className={cn(
          FLOATING_SURFACE_CLASSES,
          MENU_WIDTH,
          'scroll-cue bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 z-50 max-h-(--radix-dropdown-menu-content-available-height) origin-(--radix-dropdown-menu-content-transform-origin) overflow-x-hidden overflow-y-auto rounded-md border p-1 shadow-md',
          className
        )}
        {...props}
      />
    </DropdownMenuPrimitive.Portal>
  )
}

function DropdownMenuGroup({ ...props }: React.ComponentProps<typeof DropdownMenuPrimitive.Group>) {
  return <DropdownMenuPrimitive.Group data-slot="dropdown-menu-group" {...props} />
}

function DropdownMenuItem({
  className,
  inset,
  variant = 'default',
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.Item> & {
  inset?: boolean
  variant?: 'default' | 'destructive'
}) {
  return (
    <DropdownMenuPrimitive.Item
      data-slot="dropdown-menu-item"
      data-inset={inset}
      data-variant={variant}
      className={cn(
        "focus:bg-hov focus:text-accent-foreground data-[variant=destructive]:text-destructive data-[variant=destructive]:focus:bg-destructive/10 dark:data-[variant=destructive]:focus:bg-destructive/20 data-[variant=destructive]:focus:text-destructive data-[variant=destructive]:*:[svg]:!text-destructive [&_svg:not([class*='text-'])]:text-muted-foreground relative flex cursor-default items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-hidden select-none data-[disabled]:pointer-events-none data-[disabled]:opacity-50 data-[inset]:ps-8 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
        className
      )}
      {...props}
    />
  )
}

function DropdownMenuCheckboxItem({
  className,
  children,
  checked,
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.CheckboxItem>) {
  return (
    <DropdownMenuPrimitive.CheckboxItem
      data-slot="dropdown-menu-checkbox-item"
      className={cn(
        "focus:bg-hov focus:text-accent-foreground relative flex cursor-default items-center gap-2 rounded-sm py-1.5 pe-2 ps-8 text-sm outline-hidden select-none data-[disabled]:pointer-events-none data-[disabled]:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
        className
      )}
      checked={checked}
      {...props}
    >
      <span className="pointer-events-none absolute left-2 flex size-3.5 items-center justify-center">
        <DropdownMenuPrimitive.ItemIndicator>
          <CheckIcon className="size-4" />
        </DropdownMenuPrimitive.ItemIndicator>
      </span>
      {children}
    </DropdownMenuPrimitive.CheckboxItem>
  )
}

function DropdownMenuRadioGroup({
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.RadioGroup>) {
  return <DropdownMenuPrimitive.RadioGroup data-slot="dropdown-menu-radio-group" {...props} />
}

function DropdownMenuRadioItem({
  className,
  children,
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.RadioItem>) {
  return (
    <DropdownMenuPrimitive.RadioItem
      data-slot="dropdown-menu-radio-item"
      className={cn(
        "focus:bg-hov focus:text-accent-foreground relative flex cursor-default items-center gap-2 rounded-sm py-1.5 pe-2 ps-8 text-sm outline-hidden select-none data-[disabled]:pointer-events-none data-[disabled]:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
        className
      )}
      {...props}
    >
      <span className="pointer-events-none absolute left-2 flex size-3.5 items-center justify-center">
        <DropdownMenuPrimitive.ItemIndicator>
          <CircleIcon className="size-2 fill-current" />
        </DropdownMenuPrimitive.ItemIndicator>
      </span>
      {children}
    </DropdownMenuPrimitive.RadioItem>
  )
}

const MENU_ITEM = '[role="menuitem"],[role="menuitemcheckbox"],[role="menuitemradio"]'

/**
 * Number of menu items a label heads: the items of its `DropdownMenuGroup`,
 * or else the items after it up to the next separator or label.
 */
export function countLabelledItems(label: HTMLElement): number {
  const parent = label.parentElement
  if (parent?.getAttribute('role') === 'group') return parent.querySelectorAll(MENU_ITEM).length
  let n = 0
  for (let el = label.nextElementSibling; el; el = el.nextElementSibling) {
    const slot = el.getAttribute('data-slot')
    if (el.getAttribute('role') === 'separator' || slot === 'dropdown-menu-label') break
    n += el.matches(MENU_ITEM) ? 1 : el.querySelectorAll(MENU_ITEM).length
  }
  return n
}

/**
 * A group heading. A heading over a single item says nothing the item does
 * not, so it hides itself when its group has exactly one item (a label over
 * no items, such as the signed-in account at the top of a menu, stays).
 */
function DropdownMenuLabel({
  className,
  inset,
  ref,
  hidden,
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.Label> & {
  inset?: boolean
}) {
  const own = React.useRef<HTMLDivElement | null>(null)
  const [single, setSingle] = React.useState(false)
  // Every render: the items under it can change with permissions or data.
  // setSingle bails out when the answer is unchanged, so this settles.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  React.useLayoutEffect(() => {
    const el = own.current
    if (el) setSingle(countLabelledItems(el) === 1)
  })
  const setRef = React.useCallback(
    (node: HTMLDivElement | null) => {
      own.current = node
      if (typeof ref === 'function') ref(node)
      else if (ref) ref.current = node
    },
    [ref]
  )
  return (
    <DropdownMenuPrimitive.Label
      ref={setRef}
      data-slot="dropdown-menu-label"
      data-inset={inset}
      hidden={hidden || single}
      className={cn('px-2 py-1.5 text-sm font-medium data-[inset]:ps-8', className)}
      {...props}
    />
  )
}

function DropdownMenuSeparator({
  className,
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.Separator>) {
  return (
    <DropdownMenuPrimitive.Separator
      data-slot="dropdown-menu-separator"
      className={cn('bg-border -mx-1 my-1 h-px', className)}
      {...props}
    />
  )
}

function DropdownMenuShortcut({ className, ...props }: React.ComponentProps<'span'>) {
  return (
    <span
      data-slot="dropdown-menu-shortcut"
      // A shortcut hint means nothing without a keyboard: hidden under a
      // coarse pointer (phones, touch tablets).
      className={cn(
        'text-muted-foreground ms-auto text-cap tracking-widest pointer-coarse:hidden',
        className
      )}
      {...props}
    />
  )
}

function DropdownMenuSub({ ...props }: React.ComponentProps<typeof DropdownMenuPrimitive.Sub>) {
  return <DropdownMenuPrimitive.Sub data-slot="dropdown-menu-sub" {...props} />
}

function DropdownMenuSubTrigger({
  className,
  inset,
  children,
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.SubTrigger> & {
  inset?: boolean
}) {
  return (
    <DropdownMenuPrimitive.SubTrigger
      data-slot="dropdown-menu-sub-trigger"
      data-inset={inset}
      className={cn(
        "focus:bg-hov focus:text-accent-foreground data-[state=open]:bg-hov data-[state=open]:text-accent-foreground flex cursor-default items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-hidden select-none data-[inset]:ps-8 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4 [&_svg:not([class*='text-'])]:text-muted-foreground",
        className
      )}
      {...props}
    >
      {children}
      <ChevronRightIcon className="ms-auto size-4" />
    </DropdownMenuPrimitive.SubTrigger>
  )
}

function DropdownMenuSubContent({
  className,
  collisionPadding = FLOATING_COLLISION_PADDING,
  style,
  ref,
  ...props
}: React.ComponentProps<typeof DropdownMenuPrimitive.SubContent>) {
  const floating = useFloatingContent({
    side: 'right',
    collisionPadding,
    fallbackAlign: 'start',
  })
  const { attach } = floating
  const contentRef = React.useCallback(
    (node: HTMLDivElement | null) => {
      attach(node)
      if (typeof ref === 'function') ref(node)
      else if (ref) ref.current = node
    },
    [ref, attach]
  )
  return (
    <DropdownMenuPrimitive.SubContent
      ref={contentRef}
      data-slot="dropdown-menu-sub-content"
      collisionPadding={floating.collisionPadding}
      style={{ ...floating.style, ...style }}
      className={cn(
        FLOATING_SURFACE_CLASSES,
        SUBMENU_WIDTH,
        'scroll-cue bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 z-50 max-h-(--radix-dropdown-menu-content-available-height) origin-(--radix-dropdown-menu-content-transform-origin) overflow-x-hidden overflow-y-auto rounded-md border p-1 shadow-lg',
        className
      )}
      {...props}
    />
  )
}

export {
  DropdownMenu,
  DropdownMenuPortal,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuLabel,
  DropdownMenuItem,
  DropdownMenuCheckboxItem,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
  DropdownMenuSub,
  DropdownMenuSubTrigger,
  DropdownMenuSubContent,
}
