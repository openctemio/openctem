'use client'

import * as React from 'react'
import * as AlertDialogPrimitive from '@radix-ui/react-alert-dialog'

import { cn } from '@/lib/utils'
import { buttonVariants } from '@/components/ui/button'
import {
  MODAL_SIZE,
  ModalBody,
  ModalLayoutContext,
  type ModalSize,
  footerSectionClass,
  headerSectionClass,
  modalSurfaceClassName,
  useKeyboardInset,
  useModalLayout,
  useModalLayoutState,
} from '@/components/ui/modal-layout'

function AlertDialog({ ...props }: React.ComponentProps<typeof AlertDialogPrimitive.Root>) {
  return <AlertDialogPrimitive.Root data-slot="alert-dialog" {...props} />
}

function AlertDialogTrigger({
  ...props
}: React.ComponentProps<typeof AlertDialogPrimitive.Trigger>) {
  return <AlertDialogPrimitive.Trigger data-slot="alert-dialog-trigger" {...props} />
}

function AlertDialogPortal({ ...props }: React.ComponentProps<typeof AlertDialogPrimitive.Portal>) {
  return <AlertDialogPrimitive.Portal data-slot="alert-dialog-portal" {...props} />
}

function AlertDialogOverlay({
  className,
  ...props
}: React.ComponentProps<typeof AlertDialogPrimitive.Overlay>) {
  return (
    <AlertDialogPrimitive.Overlay
      data-slot="alert-dialog-overlay"
      className={cn(
        'data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 motion-reduce:animate-none fixed inset-0 z-50 bg-black/50',
        className
      )}
      {...props}
    />
  )
}

/**
 * A confirmation: the same frame as a dialog (fixed header, a body that is
 * the only part that scrolls, fixed footer; a bottom sheet on phones) with no
 * close button: the user answers with a footer action or Esc. Put anything
 * beyond the title and description (a list, a field) in AlertDialogBody.
 */
function AlertDialogContent({
  className,
  children,
  size = 'md',
  ref,
  ...props
}: React.ComponentProps<typeof AlertDialogPrimitive.Content> & { size?: ModalSize }) {
  const [node, setNode] = React.useState<HTMLDivElement | null>(null)
  const setRefs = React.useCallback(
    (el: HTMLDivElement | null) => {
      setNode(el)
      if (typeof ref === 'function') ref(el)
      else if (ref) ref.current = el
    },
    [ref]
  )
  const layout = useModalLayoutState(null)
  useKeyboardInset(node)
  return (
    <AlertDialogPortal>
      <AlertDialogOverlay />
      <AlertDialogPrimitive.Content
        ref={setRefs}
        data-slot="alert-dialog-content"
        data-layout={layout.sections ? 'sections' : 'block'}
        className={cn(
          modalSurfaceClassName,
          MODAL_SIZE[size],
          layout.sections
            ? 'flex flex-col gap-0 overflow-hidden p-0'
            : 'grid gap-4 overflow-x-hidden overflow-y-auto p-4 pb-[max(1rem,env(safe-area-inset-bottom))] sm:p-6',
          className
        )}
        {...props}
      >
        <ModalLayoutContext.Provider value={layout}>{children}</ModalLayoutContext.Provider>
      </AlertDialogPrimitive.Content>
    </AlertDialogPortal>
  )
}

function AlertDialogHeader({ className, ...props }: React.ComponentProps<'div'>) {
  const layout = useModalLayout()
  return (
    <div
      data-slot="alert-dialog-header"
      className={cn(
        layout?.sections
          ? cn(headerSectionClass, 'flex-col gap-1.5 pe-4 sm:pe-6')
          : 'flex flex-col gap-2 text-center sm:text-start',
        className
      )}
      {...props}
    />
  )
}

/** The scrolling middle of a confirmation (a list of what is affected, a field). */
function AlertDialogBody(props: React.ComponentProps<'div'>) {
  return <ModalBody slot="alert-dialog-body" {...props} />
}

function AlertDialogFooter({ className, ...props }: React.ComponentProps<'div'>) {
  const layout = useModalLayout()
  return (
    <div
      data-slot="alert-dialog-footer"
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

function AlertDialogTitle({
  className,
  ...props
}: React.ComponentProps<typeof AlertDialogPrimitive.Title>) {
  return (
    <AlertDialogPrimitive.Title
      data-slot="alert-dialog-title"
      className={cn('text-lg font-semibold', className)}
      {...props}
    />
  )
}

function AlertDialogDescription({
  className,
  ...props
}: React.ComponentProps<typeof AlertDialogPrimitive.Description>) {
  return (
    <AlertDialogPrimitive.Description
      data-slot="alert-dialog-description"
      className={cn('text-muted-foreground text-sm', className)}
      {...props}
    />
  )
}

function AlertDialogAction({
  className,
  ...props
}: React.ComponentProps<typeof AlertDialogPrimitive.Action>) {
  return <AlertDialogPrimitive.Action className={cn(buttonVariants(), className)} {...props} />
}

function AlertDialogCancel({
  className,
  ...props
}: React.ComponentProps<typeof AlertDialogPrimitive.Cancel>) {
  return (
    <AlertDialogPrimitive.Cancel
      className={cn(buttonVariants({ variant: 'outline' }), className)}
      {...props}
    />
  )
}

export {
  AlertDialog,
  AlertDialogPortal,
  AlertDialogOverlay,
  AlertDialogTrigger,
  AlertDialogContent,
  AlertDialogBody,
  AlertDialogHeader,
  AlertDialogFooter,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogAction,
  AlertDialogCancel,
}
