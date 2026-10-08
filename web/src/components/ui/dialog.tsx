'use client'

import * as React from 'react'
import * as DialogPrimitive from '@radix-ui/react-dialog'
import { XIcon } from 'lucide-react'

import { cn } from '@/lib/utils'
import { ignoreToasterInteractions } from '@/components/ui/toaster-guard'
import {
  MODAL_SIZE,
  ModalBody,
  ModalForm,
  ModalLayoutContext,
  type ModalSize,
  focusModalBody,
  modalSurfaceClassName,
  footerSectionClass,
  headerSectionClass,
  useKeyboardInset,
  useModalLayout,
  useModalLayoutState,
  useOpenAutoFocus,
} from '@/components/ui/modal-layout'

function Dialog({ ...props }: React.ComponentProps<typeof DialogPrimitive.Root>) {
  return <DialogPrimitive.Root data-slot="dialog" {...props} />
}

function DialogTrigger({ ...props }: React.ComponentProps<typeof DialogPrimitive.Trigger>) {
  return <DialogPrimitive.Trigger data-slot="dialog-trigger" {...props} />
}

function DialogPortal({ ...props }: React.ComponentProps<typeof DialogPrimitive.Portal>) {
  return <DialogPrimitive.Portal data-slot="dialog-portal" {...props} />
}

function DialogClose({ ...props }: React.ComponentProps<typeof DialogPrimitive.Close>) {
  return <DialogPrimitive.Close data-slot="dialog-close" {...props} />
}

function DialogOverlay({
  className,
  ...props
}: React.ComponentProps<typeof DialogPrimitive.Overlay>) {
  return (
    <DialogPrimitive.Overlay
      data-slot="dialog-overlay"
      className={cn(
        'data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 motion-reduce:animate-none fixed inset-0 z-50 bg-black/50',
        className
      )}
      {...props}
    />
  )
}

/** The close button's look: a 44px hit area, visible focus ring. */
const dialogCloseClassName =
  'ring-offset-background focus-visible:ring-ring data-[state=open]:bg-accent data-[state=open]:text-muted-foreground rounded-md opacity-70 transition-opacity hover:opacity-100 focus-visible:opacity-100 focus-visible:ring-2 focus-visible:ring-offset-2 focus:outline-hidden disabled:pointer-events-none flex items-center justify-center h-10 w-10 min-h-[44px] min-w-[44px]'

function DialogCloseButton({ className }: { className?: string }) {
  return (
    <DialogPrimitive.Close data-slot="dialog-close" className={cn(dialogCloseClassName, className)}>
      <XIcon className="size-5" aria-hidden />
      <span className="sr-only">Close</span>
    </DialogPrimitive.Close>
  )
}

export type DialogSize = ModalSize

/**
 * A dialog: a fixed header, a body that is the only part that scrolls, and a
 * fixed footer.
 *
 *   <DialogContent size="lg">
 *     <DialogHeader>
 *       <DialogTitle>Add finding</DialogTitle>
 *       <DialogDescription>…</DialogDescription>
 *     </DialogHeader>
 *     <DialogForm onSubmit={submit}>
 *       <DialogBody>…fields…</DialogBody>
 *       <DialogFooter>…Cancel, Create…</DialogFooter>
 *     </DialogForm>
 *   </DialogContent>
 *
 * Never set `max-h-*`, `overflow-*` or `max-w-*` on the content: use `size`.
 * A dialog without a DialogBody keeps the old single padded block that
 * scrolls as a whole; that mode goes once every dialog has a body.
 */
function DialogContent({
  className,
  children,
  showCloseButton = true,
  size = 'md',
  onInteractOutside,
  onOpenAutoFocus,
  ref,
  ...props
}: React.ComponentProps<typeof DialogPrimitive.Content> & {
  /**
   * The close button: in the header row with a DialogBody, in the top-right
   * corner otherwise. Turn it off when the dialog draws a DialogHeaderBar
   * (which has its own).
   */
  showCloseButton?: boolean
  size?: DialogSize
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
    () => (showCloseButton ? <DialogCloseButton className="-my-1 shrink-0" /> : null),
    [showCloseButton]
  )
  const layout = useModalLayoutState(closeButton)
  useKeyboardInset(node)
  const autoFocus = useOpenAutoFocus(contentRef, 'dialog-body', onOpenAutoFocus)
  return (
    <DialogPortal data-slot="dialog-portal">
      <DialogOverlay />
      <DialogPrimitive.Content
        ref={setRefs}
        data-slot="dialog-content"
        data-layout={layout.sections ? 'sections' : 'block'}
        className={cn(
          modalSurfaceClassName,
          MODAL_SIZE[size],
          layout.sections
            ? 'flex flex-col gap-0 overflow-hidden p-0'
            : 'grid gap-4 overflow-x-hidden overflow-y-auto p-4 pb-[max(1rem,env(safe-area-inset-bottom))] sm:p-6',
          className
        )}
        onInteractOutside={ignoreToasterInteractions(onInteractOutside)}
        onOpenAutoFocus={autoFocus}
        {...props}
      >
        <ModalLayoutContext.Provider value={layout}>{children}</ModalLayoutContext.Provider>
        {showCloseButton && !layout.sections && (
          <DialogCloseButton className="absolute top-3 right-3" />
        )}
      </DialogPrimitive.Content>
    </DialogPortal>
  )
}

/**
 * Initial focus for a DialogHeaderBar dialog, as its `onOpenAutoFocus`
 * handler (a dialog with a DialogBody does this by itself): the body's first
 * field, or the body itself (give it `tabIndex={-1}`); on a touch screen
 * always the body, so the on-screen keyboard does not open by itself.
 *
 *   <DialogContent onOpenAutoFocus={(e) => focusDialogBody(e, bodyRef.current)}>
 */
const focusDialogBody = focusModalBody

/**
 * The chrome row of a dialog whose body is laid out edge to edge (split
 * panes, a tinted aside, a scrolling body with a sticky footer): title and
 * description on the left, the close button on the right, on the dialog's
 * own surface, above everything else. The body then starts below it, so the
 * close button never lands on a tinted region of the body.
 *
 * Use with `<DialogContent showCloseButton={false} className="flex flex-col gap-0 p-0 sm:p-0 …">`
 * (`sm:p-0` too: DialogContent pads `sm:p-6`)
 * and put DialogTitle / DialogDescription inside. Pass `focusDialogBody` as
 * the content's `onOpenAutoFocus` so the dialog does not open on the close button.
 */
function DialogHeaderBar({
  className,
  children,
  actions,
  showCloseButton = true,
  ...props
}: React.ComponentProps<'div'> & {
  /** Rendered before the close button (e.g. a status badge). */
  actions?: React.ReactNode
  showCloseButton?: boolean
}) {
  return (
    <div
      data-slot="dialog-header-bar"
      className={cn(
        'bg-background flex shrink-0 items-start gap-3 border-b py-3 ps-4 pe-2 sm:ps-6 sm:pe-3',
        className
      )}
      {...props}
    >
      <div className="flex min-w-0 flex-1 flex-col gap-1 py-1.5 text-start">{children}</div>
      {actions && <div className="flex shrink-0 items-center gap-2 py-1">{actions}</div>}
      {showCloseButton && <DialogCloseButton className="shrink-0" />}
    </div>
  )
}

/**
 * Title and description. With a DialogBody it is the fixed top row: the
 * text on the start side, then `actions` (a status badge, a menu) and the
 * close button.
 */
function DialogHeader({
  className,
  children,
  actions,
  ...props
}: React.ComponentProps<'div'> & { actions?: React.ReactNode }) {
  const layout = useModalLayout()
  if (layout?.sections) {
    return (
      <div data-slot="dialog-header" className={cn(headerSectionClass, className)} {...props}>
        <div className="flex min-w-0 flex-1 flex-col gap-1.5 text-start">{children}</div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        {layout.closeButton}
      </div>
    )
  }
  return (
    <div
      data-slot="dialog-header"
      className={cn('flex flex-col gap-2 text-center sm:text-start', className)}
      {...props}
    >
      {children}
      {actions}
    </div>
  )
}

/** The scrolling middle of a dialog: every field, list and paragraph. */
function DialogBody(props: React.ComponentProps<'div'>) {
  return <ModalBody slot="dialog-body" {...props} />
}

/** A `<form>` spanning DialogBody and DialogFooter, so Enter submits. */
const DialogForm = ModalForm

/**
 * The actions. With a DialogBody it is the fixed bottom row, always visible:
 * secondary first, primary last (on phones the primary is on top).
 */
function DialogFooter({ className, ...props }: React.ComponentProps<'div'>) {
  const layout = useModalLayout()
  return (
    <div
      data-slot="dialog-footer"
      className={cn(
        layout?.sections
          ? footerSectionClass
          : 'flex flex-col-reverse gap-2 sm:flex-row sm:justify-end',
        className
      )}
      {...props}
    />
  )
}

function DialogTitle({ className, ...props }: React.ComponentProps<typeof DialogPrimitive.Title>) {
  return (
    <DialogPrimitive.Title
      data-slot="dialog-title"
      className={cn('text-lg leading-tight font-semibold', className)}
      {...props}
    />
  )
}

function DialogDescription({
  className,
  ...props
}: React.ComponentProps<typeof DialogPrimitive.Description>) {
  return (
    <DialogPrimitive.Description
      data-slot="dialog-description"
      className={cn('text-muted-foreground text-sm', className)}
      {...props}
    />
  )
}

export {
  Dialog,
  DialogBody,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogForm,
  DialogHeader,
  DialogHeaderBar,
  DialogOverlay,
  DialogPortal,
  DialogTitle,
  DialogTrigger,
  focusDialogBody,
}
