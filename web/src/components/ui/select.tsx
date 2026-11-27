'use client'

import * as React from 'react'
import * as SelectPrimitive from '@radix-ui/react-select'
import { CheckIcon, ChevronDownIcon, ChevronUpIcon } from 'lucide-react'

import { cn } from '@/lib/utils'
import {
  FLOATING_COLLISION_PADDING,
  FLOATING_SURFACE_CLASSES,
  FloatingAnchorProvider,
  useFloatingContent,
  useFloatingRoot,
  useFloatingAnchorSetter,
} from '@/components/ui/floating'

function Select(props: React.ComponentProps<typeof SelectPrimitive.Root>) {
  const { state, onOpenChange } = useFloatingRoot(props)
  return (
    <FloatingAnchorProvider state={state}>
      <SelectPrimitive.Root data-slot="select" {...props} onOpenChange={onOpenChange} />
    </FloatingAnchorProvider>
  )
}

function SelectGroup({ ...props }: React.ComponentProps<typeof SelectPrimitive.Group>) {
  return <SelectPrimitive.Group data-slot="select-group" {...props} />
}

/**
 * The plain text parts of an option label, each in its own box. In the field
 * that box wraps when the value is longer than the field, and the field grows
 * from its height (`SELECT_TRIGGER_CLASS`): a cut value ("Mọi mức rủi…") hides
 * what is chosen. Text that sits directly in the value's flex box would be cut
 * with no mark, so every string part of a label, a placeholder or a custom
 * value goes through here.
 */
function textParts(node: React.ReactNode): React.ReactNode {
  if (typeof node === 'string' || typeof node === 'number') {
    return <span data-slot="select-text">{node}</span>
  }
  if (Array.isArray(node)) {
    // Adjacent text parts ("Name", " (", 3, ")") form one box, so the label
    // reads and cuts as one line of text.
    const out: React.ReactNode[] = []
    let text = ''
    const flush = () => {
      if (text)
        out.push(
          <span key={`t${out.length}`} data-slot="select-text">
            {text}
          </span>
        )
      text = ''
    }
    React.Children.forEach(node, (child) => {
      if (typeof child === 'string' || typeof child === 'number') text += String(child)
      else {
        flush()
        out.push(child)
      }
    })
    flush()
    return out
  }
  return node
}

function SelectValue({
  children,
  placeholder,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Value>) {
  return (
    <SelectPrimitive.Value data-slot="select-value" placeholder={textParts(placeholder)} {...props}>
      {textParts(children)}
    </SelectPrimitive.Value>
  )
}

/**
 * Icon-only below a width (a toolbar select whose value is `sr-only` there):
 * drawn as a square with no chevron, like an icon button.
 */
const SELECT_ICON_ONLY_BELOW = {
  '@2xl/toolbar': {
    trigger: '@max-2xl/toolbar:aspect-square @max-2xl/toolbar:justify-center @max-2xl/toolbar:px-0',
    chevron: '@max-2xl/toolbar:hidden',
  },
  '@5xl/toolbar': {
    trigger:
      '@max-5xl/toolbar:aspect-square @max-5xl/toolbar:justify-center @max-5xl/toolbar:px-0 group-data-[fold=true]/toolbar:aspect-square group-data-[fold=true]/toolbar:justify-center group-data-[fold=true]/toolbar:px-0',
    chevron: '@max-5xl/toolbar:hidden group-data-[fold=true]/toolbar:hidden',
  },
} as const

/**
 * The look of a select field. A picker that opens a popover of its own (a
 * searchable list) draws its trigger with this class and `data-size`, so every
 * field of a form has one border, height, text size and chevron. A default-size
 * select has 16px text below 768px, like `Input` (one field look per form).
 */
export const SELECT_TRIGGER_CLASS =
  "border-input data-[placeholder]:text-muted-foreground [&_svg:not([class*='text-'])]:text-muted-foreground focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive dark:bg-input/30 dark:hover:bg-input/50 flex w-fit items-center justify-between gap-2 rounded-md border bg-transparent px-3 py-1 text-start text-body shadow-xs transition-[color,box-shadow] outline-none focus-visible:ring-[3px] disabled:cursor-not-allowed disabled:opacity-50 data-[size=default]:min-h-control-field data-[size=sm]:min-h-control-dense max-md:data-[size=default]:min-h-control-touch max-md:data-[size=default]:text-base max-md:data-[size=sm]:min-h-control-touch-dense *:data-[slot=select-value]:flex *:data-[slot=select-value]:min-w-0 *:data-[slot=select-value]:overflow-hidden **:data-[slot=select-text]:min-w-0 **:data-[slot=select-text]:break-words *:data-[slot=select-value]:items-center *:data-[slot=select-value]:gap-2 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4" // design-ok: text-base (16px) on phone fields keeps phones from zooming, as Input

/**
 * Whether the last input was the keyboard. Radix Select gives the focus back
 * to its trigger by script when it closes; after a pointer choice Chrome
 * still matches `:focus-visible` there (the trigger never took the pointer's
 * focus: Radix cancels its pointerdown), so a mouse user saw the keyboard
 * ring at rest. The trigger marks a focus that did not follow a key
 * (`data-pointer-focus`) and draws no ring for it; Tab and the arrow keys
 * still show it.
 */
let lastInputKeyboard = false
let modalityListening = false
function listenForInputModality() {
  if (modalityListening || typeof window === 'undefined') return
  modalityListening = true
  window.addEventListener(
    'keydown',
    (e) => {
      if (!e.metaKey && !e.ctrlKey && !e.altKey) lastInputKeyboard = true
    },
    true
  )
  window.addEventListener('pointerdown', () => (lastInputKeyboard = false), true)
}

function SelectTrigger({
  className,
  size = 'default',
  iconOnlyBelow,
  children,
  ref,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Trigger> & {
  size?: 'sm' | 'default'
  /** Icon-only below this toolbar width: a square with no chevron. */
  iconOnlyBelow?: keyof typeof SELECT_ICON_ONLY_BELOW
}) {
  const iconOnly = iconOnlyBelow ? SELECT_ICON_ONLY_BELOW[iconOnlyBelow] : undefined
  const record = useFloatingAnchorSetter()
  React.useEffect(listenForInputModality, [])
  const { onFocus } = props
  const triggerRef = React.useCallback(
    (node: HTMLButtonElement | null) => {
      if (typeof ref === 'function') ref(node)
      else if (ref) ref.current = node
      record(node)
    },
    [ref, record]
  )
  return (
    <SelectPrimitive.Trigger
      ref={triggerRef}
      data-slot="select-trigger"
      data-size={size}
      className={cn(
        SELECT_TRIGGER_CLASS,
        'data-[pointer-focus]:focus-visible:border-input data-[pointer-focus]:focus-visible:ring-0',
        iconOnly?.trigger,
        className
      )}
      {...props}
      onFocus={(e) => {
        e.currentTarget.toggleAttribute('data-pointer-focus', !lastInputKeyboard)
        onFocus?.(e)
      }}
    >
      {children}
      <SelectPrimitive.Icon asChild>
        <ChevronDownIcon className={cn('size-4 opacity-50', iconOnly?.chevron)} />
      </SelectPrimitive.Icon>
    </SelectPrimitive.Trigger>
  )
}

/**
 * The option list: below its trigger (above when there is no room), never
 * laid over it, at least as wide as it, lined up with the trigger's start
 * edge unless that would cross the room it has (`chooseAlign`).
 */
function SelectContent({
  className,
  children,
  position = 'popper',
  align,
  side,
  collisionPadding = FLOATING_COLLISION_PADDING,
  style,
  ref,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Content>) {
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
    <SelectPrimitive.Portal>
      <SelectPrimitive.Content
        ref={contentRef}
        data-slot="select-content"
        style={position === 'popper' ? { ...floating.style, ...style } : style}
        className={cn(
          FLOATING_SURFACE_CLASSES,
          'bg-popover text-popover-foreground data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 relative z-50 max-h-(--radix-select-content-available-height) min-w-[8rem] origin-(--radix-select-content-transform-origin) overflow-x-hidden overflow-y-auto rounded-md border shadow-md',
          position === 'popper' &&
            'data-[side=bottom]:translate-y-1 data-[side=left]:-translate-x-1 data-[side=right]:translate-x-1 data-[side=top]:-translate-y-1',
          className
        )}
        position={position}
        side={side}
        align={floating.align}
        collisionPadding={floating.collisionPadding}
        {...props}
      >
        <SelectScrollUpButton />
        <SelectPrimitive.Viewport
          className={cn(
            'p-1',
            position === 'popper' &&
              'h-[var(--radix-select-trigger-height)] w-full min-w-[var(--radix-select-trigger-width)] scroll-my-1'
          )}
        >
          {children}
        </SelectPrimitive.Viewport>
        <SelectScrollDownButton />
      </SelectPrimitive.Content>
    </SelectPrimitive.Portal>
  )
}

function SelectLabel({ className, ...props }: React.ComponentProps<typeof SelectPrimitive.Label>) {
  return (
    <SelectPrimitive.Label
      data-slot="select-label"
      className={cn('text-muted-foreground px-2 py-1.5 text-xs', className)}
      {...props}
    />
  )
}

function SelectItem({
  className,
  children,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Item>) {
  return (
    <SelectPrimitive.Item
      data-slot="select-item"
      className={cn(
        "focus:bg-hov focus:text-accent-foreground [&_svg:not([class*='text-'])]:text-muted-foreground relative flex w-full cursor-default items-center gap-2 rounded-sm py-1.5 pe-8 ps-2 text-sm outline-hidden select-none data-[disabled]:pointer-events-none data-[disabled]:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4 *:[span]:last:flex *:[span]:last:items-center *:[span]:last:gap-2",
        className
      )}
      {...props}
    >
      <span
        data-slot="select-item-indicator"
        className="absolute right-2 flex size-3.5 items-center justify-center"
      >
        <SelectPrimitive.ItemIndicator>
          <CheckIcon className="size-4" />
        </SelectPrimitive.ItemIndicator>
      </span>
      <SelectPrimitive.ItemText>{textParts(children)}</SelectPrimitive.ItemText>
    </SelectPrimitive.Item>
  )
}

function SelectSeparator({
  className,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.Separator>) {
  return (
    <SelectPrimitive.Separator
      data-slot="select-separator"
      className={cn('bg-border pointer-events-none -mx-1 my-1 h-px', className)}
      {...props}
    />
  )
}

function SelectScrollUpButton({
  className,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.ScrollUpButton>) {
  return (
    <SelectPrimitive.ScrollUpButton
      data-slot="select-scroll-up-button"
      className={cn('flex cursor-default items-center justify-center py-1', className)}
      {...props}
    >
      <ChevronUpIcon className="size-4" />
    </SelectPrimitive.ScrollUpButton>
  )
}

function SelectScrollDownButton({
  className,
  ...props
}: React.ComponentProps<typeof SelectPrimitive.ScrollDownButton>) {
  return (
    <SelectPrimitive.ScrollDownButton
      data-slot="select-scroll-down-button"
      className={cn('flex cursor-default items-center justify-center py-1', className)}
      {...props}
    >
      <ChevronDownIcon className="size-4" />
    </SelectPrimitive.ScrollDownButton>
  )
}

export {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectScrollDownButton,
  SelectScrollUpButton,
  SelectSeparator,
  SelectTrigger,
  SelectValue,
}
