'use client'

import * as React from 'react'
import { Command as CommandPrimitive } from 'cmdk'
import { SearchIcon, X } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useTranslation } from '@/context/i18n-provider'
import { useSurfaceAutoFocus, type TouchTypingSurface } from '@/components/ui/touch-focus'
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { ShortcutKeys } from '@/components/layout/shortcut-keys'
import type { ShortcutKey } from '@/config/keyboard-shortcuts'

function Command({ className, ...props }: React.ComponentProps<typeof CommandPrimitive>) {
  return (
    <CommandPrimitive
      data-slot="command"
      className={cn(
        'bg-popover text-popover-foreground flex h-full w-full flex-col overflow-hidden rounded-md',
        className
      )}
      {...props}
    />
  )
}

/**
 * The palette surface. One surface: the search field on its top edge, the
 * list below it (the only part that scrolls) and an optional footer.
 * Phones: a full-height sheet from the top, above the on-screen keyboard.
 * From `sm`: 640 px wide, 15% from the top, at most 70% of the screen tall.
 */
const PALETTE_SURFACE = cn(
  'bg-popover text-popover-foreground flex flex-col gap-0 overflow-hidden p-0 sm:p-0 pb-[env(safe-area-inset-bottom)] shadow-[var(--shadow-overlay)]',
  'top-0 max-h-none rounded-none border-0 pt-[env(safe-area-inset-top)]',
  'sm:top-[15dvh] sm:translate-y-0 sm:max-h-[min(70dvh,36rem)] sm:max-w-[40rem] sm:rounded-xl sm:border sm:pt-0 sm:pb-0',
  'data-[state=open]:slide-in-from-top-2! data-[state=closed]:slide-out-to-top-2!'
)

/**
 * Rows and headings inside the palette: compact rows (36 px from `sm`, a
 * 44 px touch row on a phone), small muted headings, muted 16 px icons, and
 * a selected row that is clearly marked (`bg-sel`, its icon in the text colour).
 */
const PALETTE_LIST = cn(
  'flex min-h-0 flex-1 flex-col rounded-none bg-transparent',
  '[&_[cmdk-list]]:max-h-none [&_[cmdk-list]]:min-h-0 [&_[cmdk-list]]:flex-1 [&_[cmdk-list]]:overscroll-contain [&_[cmdk-list]]:py-1',
  '[&_[cmdk-group]]:px-2 [&_[cmdk-group]]:py-1 [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:pt-2 [&_[cmdk-group-heading]]:pb-1',
  '[&_[cmdk-item]]:min-h-11 sm:[&_[cmdk-item]]:min-h-9 [&_[cmdk-item]]:gap-3 [&_[cmdk-item]]:rounded-md [&_[cmdk-item]]:px-2',
  '[&_[cmdk-item][data-selected=true]]:bg-sel [&_[cmdk-item][data-selected=true]_svg]:text-foreground [&_[cmdk-item]_svg]:size-4'
)

/** Set inside a CommandDialog: the search field then carries the close control. */
const CommandDialogContext = React.createContext(false)

function CommandDialog({
  title = 'Command Palette',
  description = 'Search for a command to run...',
  children,
  className,
  footer,
  filter,
  typingSurface = 'command-menu',
  ...props
}: React.ComponentProps<typeof Dialog> & {
  title?: string
  description?: string
  className?: string
  /** Below the list, from `sm` (e.g. `CommandFooter` with keyboard hints). */
  footer?: React.ReactNode
  /** A palette is for typing: its search gets focus on open on a touch screen too. */
  typingSurface?: TouchTypingSurface
  /** cmdk filter; omit for cmdk's default fuzzy score. */
  filter?: React.ComponentProps<typeof CommandPrimitive>['filter']
}) {
  return (
    <Dialog {...props}>
      <DialogContent
        // Esc closes it; the search field has the close control
        // (CommandInput), so the corner button never covers the field.
        showCloseButton={false}
        typingSurface={typingSurface}
        overlayClassName="bg-black/60"
        className={cn(PALETTE_SURFACE, className)}
      >
        <DialogHeader className="sr-only">
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <CommandDialogContext.Provider value>
          <Command filter={filter} className={PALETTE_LIST}>
            {children}
          </Command>
          {footer}
        </CommandDialogContext.Provider>
      </DialogContent>
    </Dialog>
  )
}

/**
 * The palette's bottom row: keyboard hints (`CommandKeyHint`). Shown from
 * `sm` only; a phone has no keyboard to hint at.
 */
function CommandFooter({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="command-footer"
      className={cn(
        'text-muted-foreground border-border-subtle hidden h-10 shrink-0 items-center gap-4 border-t px-4 text-xs sm:flex',
        className
      )}
      {...props}
    />
  )
}

/** One hint in a CommandFooter: its key caps, then what they do. */
function CommandKeyHint({
  keys,
  children,
  className,
}: {
  keys: ShortcutKey[][]
  children: React.ReactNode
  className?: string
}) {
  return (
    <span className={cn('flex items-center gap-1.5', className)}>
      {keys.map((k) => (
        <ShortcutKeys key={k.join('+')} keys={k} />
      ))}
      <span>{children}</span>
    </span>
  )
}

/**
 * The search field of a `Command`. Inside a floating surface on a touch
 * screen its `autoFocus` is dropped (`touch-focus.ts`). With text in it, a
 * clear button empties it without taking the focus, so an open keyboard
 * stays open. In a CommandDialog it is the palette's top edge and ends with
 * the close control: an "Esc" key cap from `sm`, a Close button on a phone.
 */
function CommandInput({
  className,
  autoFocus,
  value,
  onValueChange,
  ...props
}: React.ComponentProps<typeof CommandPrimitive.Input>) {
  const { t } = useTranslation()
  const inDialog = React.useContext(CommandDialogContext)
  const focusOnMount = useSurfaceAutoFocus(autoFocus)
  const inputRef = React.useRef<HTMLInputElement>(null)
  const [ownValue, setOwnValue] = React.useState('')
  const controlled = value !== undefined
  const current = controlled ? value : ownValue
  const change = React.useCallback(
    (next: string) => {
      if (!controlled) setOwnValue(next)
      onValueChange?.(next)
    },
    [controlled, onValueChange]
  )
  return (
    <div
      data-slot="command-input-wrapper"
      className={cn(
        'flex items-center gap-2 border-b px-3',
        inDialog ? 'border-border-subtle h-14 shrink-0 gap-3 ps-4 pe-2 sm:h-12 sm:pe-3' : 'h-9'
      )}
    >
      <SearchIcon
        className={cn('shrink-0', inDialog ? 'text-muted-foreground size-5' : 'size-4 opacity-50')}
        aria-hidden="true"
      />
      <CommandPrimitive.Input
        ref={inputRef}
        data-slot="command-input"
        // A search box: the phone keyboard shows "Search", and 16px text
        // below `md` keeps iOS from zooming the page on focus.
        inputMode="search"
        enterKeyHint="search"
        autoFocus={focusOnMount}
        value={current}
        onValueChange={change}
        className={cn(
          'placeholder:text-muted-foreground flex h-10 w-full min-w-0 rounded-md bg-transparent py-3 text-base outline-hidden disabled:cursor-not-allowed disabled:opacity-50',
          !inDialog && 'md:text-sm',
          className
        )}
        {...props}
      />
      {current ? (
        <button
          type="button"
          data-slot="command-input-clear"
          aria-label={t('common.listSearch.clear', 'Clear search')}
          // Pressing it must not move the focus: the field keeps it, and the
          // on-screen keyboard stays up.
          onMouseDown={(e) => e.preventDefault()}
          onClick={(e) => {
            change('')
            if (document.activeElement === e.currentTarget) inputRef.current?.focus()
          }}
          className="-me-2 flex size-8 shrink-0 items-center justify-center rounded-sm text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none max-md:size-11"
        >
          <X className="size-4" aria-hidden="true" />
        </button>
      ) : null}
      {inDialog && (
        <>
          <DialogClose
            data-slot="command-close"
            className="text-muted-foreground hover:text-foreground focus-visible:ring-ring hidden h-6 shrink-0 items-center rounded border bg-muted px-1.5 font-sans text-xs font-medium focus-visible:ring-2 focus-visible:outline-none sm:inline-flex"
          >
            {/* The key cap is its label; the name says what it does too. */}
            Esc<span className="sr-only"> {t('common.close', 'Close')}</span>
          </DialogClose>
          <DialogClose asChild>
            <Button data-slot="command-close-touch" variant="ghost" className="shrink-0 sm:hidden">
              {t('common.close', 'Close')}
            </Button>
          </DialogClose>
        </>
      )}
    </div>
  )
}

function CommandList({ className, ...props }: React.ComponentProps<typeof CommandPrimitive.List>) {
  return (
    <CommandPrimitive.List
      data-slot="command-list"
      className={cn('max-h-[300px] scroll-py-1 overflow-x-hidden overflow-y-auto', className)}
      {...props}
    />
  )
}

function CommandEmpty({ ...props }: React.ComponentProps<typeof CommandPrimitive.Empty>) {
  return (
    <CommandPrimitive.Empty
      data-slot="command-empty"
      className="py-6 text-center text-sm"
      {...props}
    />
  )
}

function CommandGroup({
  className,
  ...props
}: React.ComponentProps<typeof CommandPrimitive.Group>) {
  return (
    <CommandPrimitive.Group
      data-slot="command-group"
      className={cn(
        'text-foreground [&_[cmdk-group-heading]]:text-muted-foreground overflow-hidden p-1 [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5 [&_[cmdk-group-heading]]:text-xs [&_[cmdk-group-heading]]:font-medium',
        className
      )}
      {...props}
    />
  )
}

function CommandSeparator({
  className,
  ...props
}: React.ComponentProps<typeof CommandPrimitive.Separator>) {
  return (
    <CommandPrimitive.Separator
      data-slot="command-separator"
      className={cn('bg-border -mx-1 h-px', className)}
      {...props}
    />
  )
}

function CommandItem({ className, ...props }: React.ComponentProps<typeof CommandPrimitive.Item>) {
  return (
    <CommandPrimitive.Item
      data-slot="command-item"
      className={cn(
        "data-[selected=true]:bg-hov data-[selected=true]:text-accent-foreground [&_svg:not([class*='text-'])]:text-muted-foreground relative flex cursor-default items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-hidden select-none data-[disabled=true]:pointer-events-none data-[disabled=true]:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
        className
      )}
      {...props}
    />
  )
}

function CommandShortcut({ className, ...props }: React.ComponentProps<'span'>) {
  return (
    <span
      data-slot="command-shortcut"
      className={cn('text-muted-foreground ms-auto text-xs tracking-widest', className)}
      {...props}
    />
  )
}

export {
  Command,
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandShortcut,
  CommandSeparator,
  CommandFooter,
  CommandKeyHint,
}
