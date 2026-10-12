'use client'

import * as React from 'react'
import * as SheetPrimitive from '@radix-ui/react-dialog'
import { XIcon } from 'lucide-react'

import { cn } from '@/lib/utils'
import { ignoreToasterInteractions } from '@/components/ui/toaster-guard'
import {
  ModalBody,
  ModalForm,
  ModalLayoutContext,
  footerSectionClass,
  headerSectionClass,
  useKeyboardInset,
  useModalLayout,
  useModalLayoutState,
  useOpenAutoFocus,
} from '@/components/ui/modal-layout'

function Sheet({ ...props }: React.ComponentProps<typeof SheetPrimitive.Root>) {
  return <SheetPrimitive.Root data-slot="sheet" {...props} />
}

function SheetTrigger({ ...props }: React.ComponentProps<typeof SheetPrimitive.Trigger>) {
  return <SheetPrimitive.Trigger data-slot="sheet-trigger" {...props} />
}

function SheetClose({ ...props }: React.ComponentProps<typeof SheetPrimitive.Close>) {
  return <SheetPrimitive.Close data-slot="sheet-close" {...props} />
}

function SheetPortal({ ...props }: React.ComponentProps<typeof SheetPrimitive.Portal>) {
  return <SheetPrimitive.Portal data-slot="sheet-portal" {...props} />
}

function SheetOverlay({
  className,
  ...props
}: React.ComponentProps<typeof SheetPrimitive.Overlay>) {
  return (
    <SheetPrimitive.Overlay
      data-slot="sheet-overlay"
      className={cn(
        'data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 motion-reduce:animate-none fixed inset-0 z-50 bg-black/50',
        className
      )}
      {...props}
    />
  )
}

const sheetCloseClassName =
  'ring-offset-background focus-visible:ring-ring data-[state=open]:bg-secondary rounded-md opacity-70 transition-opacity hover:opacity-100 focus-visible:opacity-100 focus-visible:ring-2 focus-visible:ring-offset-2 focus:outline-hidden disabled:pointer-events-none flex items-center justify-center h-10 w-10 min-h-[44px] min-w-[44px]'

function SheetCloseButton({ className }: { className?: string }) {
  return (
    <SheetPrimitive.Close data-slot="sheet-close" className={cn(sheetCloseClassName, className)}>
      <XIcon className="size-5" aria-hidden />
      <span className="sr-only">Close</span>
    </SheetPrimitive.Close>
  )
}

/**
 * A side panel with the dialog frame: a fixed SheetHeader (title, actions,
 * close), a SheetBody that is the only part that scrolls, an optional fixed
 * SheetFooter. The panel ends above the on-screen keyboard.
 *
 *   <SheetContent>
 *     <SheetHeader actions={…}><SheetTitle>…</SheetTitle></SheetHeader>
 *     <SheetBody>…</SheetBody>
 *     <SheetFooter>…</SheetFooter>
 *   </SheetContent>
 *
 * Never set `overflow-*` on the content. A sheet without a SheetBody keeps
 * the old layout (padded parts, corner close button, scrolls as a whole).
 */
function SheetContent({
  className,
  children,
  side = 'right',
  showCloseButton = true,
  onInteractOutside,
  onOpenAutoFocus,
  ref,
  ...props
}: React.ComponentProps<typeof SheetPrimitive.Content> & {
  side?: 'top' | 'right' | 'bottom' | 'left'
  showCloseButton?: boolean
}) {
  const contentRef = React.useRef<HTMLDivElement | null>(null)
  const [node, setNode] = React.useState<HTMLDivElement | null>(null)
  const setRefs = React.useCallback(
    (el: HTMLDivElement | null) => {
      contentRef.current = el
      setNode(el)
      if (typeof ref === 'function') ref(el)
      else if (ref) ref.current = el
    },
    [ref]
  )
  const closeButton = React.useMemo(
    () => (showCloseButton ? <SheetCloseButton className="-my-1 shrink-0" /> : null),
    [showCloseButton]
  )
  const layout = useModalLayoutState(closeButton)
  useKeyboardInset(node)
  const autoFocus = useOpenAutoFocus(contentRef, 'sheet-body', onOpenAutoFocus)
  return (
    <SheetPortal>
      <SheetOverlay />
      <SheetPrimitive.Content
        ref={setRefs}
        data-slot="sheet-content"
        data-layout={layout.sections ? 'sections' : 'block'}
        className={cn(
          'bg-background data-[state=open]:animate-in data-[state=closed]:animate-out motion-reduce:animate-none fixed z-50 flex flex-col shadow-lg transition ease-in-out data-[state=closed]:duration-300 data-[state=open]:duration-500',
          layout.sections ? 'gap-0 overflow-hidden' : 'gap-4 overflow-y-auto',
          side === 'right' &&
            'data-[state=closed]:slide-out-to-right data-[state=open]:slide-in-from-right top-0 right-0 bottom-[var(--modal-kb,0px)] w-[calc(100%-3rem)] max-w-sm border-l',
          side === 'left' &&
            'data-[state=closed]:slide-out-to-left data-[state=open]:slide-in-from-left top-0 bottom-[var(--modal-kb,0px)] left-0 w-[calc(100%-3rem)] max-w-sm border-r',
          side === 'top' &&
            'data-[state=closed]:slide-out-to-top data-[state=open]:slide-in-from-top inset-x-0 top-0 h-auto max-h-[100dvh] border-b',
          side === 'bottom' &&
            'data-[state=closed]:slide-out-to-bottom data-[state=open]:slide-in-from-bottom inset-x-0 bottom-[var(--modal-kb,0px)] h-auto max-h-[calc(100dvh-var(--modal-kb,0px))] border-t',
          className
        )}
        onInteractOutside={ignoreToasterInteractions(onInteractOutside)}
        onOpenAutoFocus={autoFocus}
        {...props}
      >
        <ModalLayoutContext.Provider value={layout}>{children}</ModalLayoutContext.Provider>
        {showCloseButton && !layout.sections && (
          <SheetCloseButton className="absolute top-3 right-3" />
        )}
      </SheetPrimitive.Content>
    </SheetPortal>
  )
}

/**
 * Title, description and the sheet's own actions. With a SheetBody it is the
 * fixed top row: the text, then `actions`, then the close button.
 */
function SheetHeader({
  className,
  children,
  actions,
  ...props
}: React.ComponentProps<'div'> & { actions?: React.ReactNode }) {
  const layout = useModalLayout()
  if (layout?.sections) {
    return (
      <div data-slot="sheet-header" className={cn(headerSectionClass, className)} {...props}>
        <div className="flex min-w-0 flex-1 flex-col gap-1.5 text-start">{children}</div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        {layout.closeButton}
      </div>
    )
  }
  return (
    <div data-slot="sheet-header" className={cn('flex flex-col gap-1.5 p-4', className)} {...props}>
      {children}
      {actions}
    </div>
  )
}

/** The scrolling middle of a sheet. */
function SheetBody(props: React.ComponentProps<'div'>) {
  return <ModalBody slot="sheet-body" {...props} />
}

/** A `<form>` spanning SheetBody and SheetFooter, so Enter submits. */
const SheetForm = ModalForm

function SheetFooter({ className, ...props }: React.ComponentProps<'div'>) {
  const layout = useModalLayout()
  return (
    <div
      data-slot="sheet-footer"
      className={cn(
        layout?.sections ? footerSectionClass : 'mt-auto flex flex-col gap-2 p-4',
        className
      )}
      {...props}
    />
  )
}

function SheetTitle({ className, ...props }: React.ComponentProps<typeof SheetPrimitive.Title>) {
  return (
    <SheetPrimitive.Title
      data-slot="sheet-title"
      className={cn('text-foreground font-semibold', className)}
      {...props}
    />
  )
}

function SheetDescription({
  className,
  ...props
}: React.ComponentProps<typeof SheetPrimitive.Description>) {
  return (
    <SheetPrimitive.Description
      data-slot="sheet-description"
      className={cn('text-muted-foreground text-sm', className)}
      {...props}
    />
  )
}

export {
  Sheet,
  SheetTrigger,
  SheetClose,
  SheetContent,
  SheetHeader,
  SheetBody,
  SheetForm,
  SheetFooter,
  SheetTitle,
  SheetDescription,
}
