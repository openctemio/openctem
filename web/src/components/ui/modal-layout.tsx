'use client'

/**
 * The layout every modal surface shares (Dialog, AlertDialog, Sheet):
 *
 *   ┌ Header ─────────────── fixed: title, description, close ┐
 *   │ Body ───────────────── the only part that scrolls        │
 *   └ Footer ─────────────── fixed: the actions                ┘
 *
 * The content is a flex column capped to the viewport; the header and footer
 * never shrink, the body takes the rest and scrolls. A divider shows under the
 * header only while the body is scrolled away from its top, and above the
 * footer only while there is more below. On phones the dialog is a bottom
 * sheet that stays above the on-screen keyboard (see `useKeyboardInset`).
 *
 * A surface switches to this layout when it renders its `…Body` part; until
 * every dialog has one, a surface without a body keeps the old single padded
 * block (see `docs/ui-style-contract.md` §8 and the governance test in
 * `__tests__/modal-layout-governance.test.ts`).
 */

import * as React from 'react'

import { cn } from '@/lib/utils'

// ============================================================================
// Layout context: does this surface have a body part?
// ============================================================================

interface ModalLayout {
  /** True once a body part is mounted: header, body and footer are sections. */
  sections: boolean
  /** Called by a body part on mount; returns its unregister. */
  registerBody: () => () => void
  /** The close button the header renders in sections mode (null: none). */
  closeButton: React.ReactNode
}

const ModalLayoutContext = React.createContext<ModalLayout | null>(null)

/** For a surface's Content: the context value to provide. */
function useModalLayoutState(closeButton: React.ReactNode): ModalLayout {
  const [bodies, setBodies] = React.useState(0)
  const registerBody = React.useCallback(() => {
    setBodies((n) => n + 1)
    return () => setBodies((n) => n - 1)
  }, [])
  return React.useMemo(
    () => ({ sections: bodies > 0, registerBody, closeButton }),
    [bodies, registerBody, closeButton]
  )
}

function useModalLayout() {
  return React.useContext(ModalLayoutContext)
}

// ============================================================================
// Surface and section classes
// ============================================================================

/**
 * Width from `sm` up; phones always get the full width (a bottom sheet).
 * `md` is the default, `lg` for long forms, `xl` for editors and tables,
 * `full` for a workspace that needs the whole screen (a fixed 90% height),
 * `screen` for a full-screen editor (a canvas: edge to edge, every size).
 */
type ModalSize = 'sm' | 'md' | 'lg' | 'xl' | 'full' | 'screen'

const MODAL_SIZE: Record<ModalSize, string> = {
  sm: 'sm:max-w-md',
  md: 'sm:max-w-lg',
  lg: 'sm:max-w-2xl',
  xl: 'sm:max-w-4xl',
  full: 'sm:max-w-[min(calc(100vw-4rem),80rem)] sm:h-[90dvh]',
  screen:
    'top-0 h-dvh max-h-dvh rounded-none border-0 sm:top-0 sm:left-0 sm:h-dvh sm:max-h-dvh sm:w-screen sm:max-w-none sm:translate-x-0 sm:translate-y-0 sm:rounded-none sm:border-0',
}

/**
 * Phones: a bottom sheet, full width, lifted above the on-screen keyboard
 * (`--modal-kb`, see useKeyboardInset), never taller than the visible screen.
 * From `sm`: centred, at most 90% of the screen tall. No motion under
 * reduced motion.
 */
const modalSurfaceClassName = cn(
  // transition-none: `duration-200` times the open/close animation only; the
  // surface must follow the keyboard at once, not ease after it.
  'bg-background fixed z-50 w-full shadow-lg outline-none transition-none duration-200',
  'data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 motion-reduce:animate-none',
  'right-0 bottom-[var(--modal-kb,0px)] left-0 max-h-[calc(100dvh-var(--modal-kb,0px)-max(1rem,env(safe-area-inset-top)))] rounded-t-2xl border-t',
  'data-[state=open]:slide-in-from-bottom data-[state=closed]:slide-out-to-bottom',
  'sm:top-[50%] sm:right-auto sm:bottom-auto sm:left-[50%] sm:max-h-[90dvh] sm:w-[calc(100%-2rem)] sm:translate-x-[-50%] sm:translate-y-[-50%] sm:rounded-lg sm:border',
  'sm:data-[state=open]:slide-in-from-bottom-0 sm:data-[state=closed]:slide-out-to-bottom-0 sm:data-[state=open]:zoom-in-95 sm:data-[state=closed]:zoom-out-95'
)

/** Horizontal padding of every section; one value so edges line up. */
const SECTION_X = 'px-4 sm:px-6'

/** Header in sections mode: a row of [title + description][actions][close]. */
const headerSectionClass =
  'flex shrink-0 items-start gap-3 ps-4 pe-2 pt-3 pb-3 sm:ps-6 sm:pe-3 sm:pt-4'

/**
 * Footer in sections mode. Phones: full-width stacked buttons, primary on top,
 * 44px tall, clear of the home indicator. From `sm`: a right-aligned row.
 */
const footerSectionClass = cn(
  'flex shrink-0 flex-col-reverse gap-2 pt-3 pb-[max(0.75rem,env(safe-area-inset-bottom))] sm:flex-row sm:justify-end sm:pb-4',
  SECTION_X,
  'max-sm:[&_button]:min-h-11'
)

// ============================================================================
// Scroll edges: which side of the body has hidden content
// ============================================================================

/**
 * Marks `el` with `data-overflow-top` / `data-overflow-bottom` while content
 * is hidden above / below, so the dividers show only when they mean something.
 * Recomputed on scroll and whenever the body or its content resizes.
 */
function useScrollEdges(el: HTMLElement | null) {
  React.useEffect(() => {
    if (!el) return
    const update = () => {
      const top = el.scrollTop > 0
      const bottom = el.scrollTop + el.clientHeight < el.scrollHeight - 1
      el.toggleAttribute('data-overflow-top', top)
      el.toggleAttribute('data-overflow-bottom', bottom)
    }
    update()
    el.addEventListener('scroll', update, { passive: true })
    // Content that grows or shrinks (a field revealed by a toggle) resizes a
    // child of the body, not the body: watch the children's sizes, and only
    // the body's own child list for new children. Never the whole subtree: a
    // long form re-renders constantly while typing.
    let frame = 0
    const later = () => {
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(update)
    }
    let ro: ResizeObserver | undefined
    if (typeof ResizeObserver !== 'undefined') {
      ro = new ResizeObserver(later)
      ro.observe(el)
      for (const child of Array.from(el.children)) ro.observe(child)
    }
    let mo: MutationObserver | undefined
    if (typeof MutationObserver !== 'undefined') {
      mo = new MutationObserver(() => {
        later()
        if (ro) for (const child of Array.from(el.children)) ro.observe(child)
      })
      mo.observe(el, { childList: true })
    }
    return () => {
      cancelAnimationFrame(frame)
      el.removeEventListener('scroll', update)
      ro?.disconnect()
      mo?.disconnect()
    }
  }, [el])
}

// ============================================================================
// On-screen keyboard
// ============================================================================

const TEXT_ENTRY =
  'input:not([type=checkbox]):not([type=radio]):not([type=button]):not([type=submit]):not([type=range]), textarea, [contenteditable=""], [contenteditable="true"]'

/**
 * Keeps a modal above the on-screen keyboard. A phone keyboard shrinks the
 * visual viewport but not the layout viewport that `position: fixed` and
 * `dvh` follow, so a bottom sheet would sit under it. This writes the covered
 * height to `--modal-kb` on `el` (the surface lifts itself by it and loses it
 * from its max height) and scrolls the focused field back into view inside the
 * body once the body has shrunk. Zero, and so a no-op, on a desktop.
 */
function useKeyboardInset(el: HTMLElement | null) {
  React.useEffect(() => {
    const vv = typeof window !== 'undefined' ? window.visualViewport : null
    if (!el || !vv) return
    let frame = 0
    let timer: ReturnType<typeof setTimeout> | undefined
    let last = 0
    const revealFocused = () => {
      const active = document.activeElement
      if (active instanceof HTMLElement && el.contains(active) && active.matches(TEXT_ENTRY)) {
        active.scrollIntoView?.({ block: 'nearest', inline: 'nearest' })
      }
    }
    const update = () => {
      const covered = Math.max(0, Math.round(window.innerHeight - vv.height - vv.offsetTop))
      if (covered === last) return
      const grew = covered > last
      last = covered
      el.style.setProperty('--modal-kb', `${covered}px`)
      if (!grew) return
      // Once the body has its new height: next frame, and again after a
      // sheet's slide transition has settled.
      cancelAnimationFrame(frame)
      clearTimeout(timer)
      frame = requestAnimationFrame(revealFocused)
      timer = setTimeout(revealFocused, 350)
    }
    update()
    vv.addEventListener('resize', update)
    vv.addEventListener('scroll', update)
    return () => {
      cancelAnimationFrame(frame)
      clearTimeout(timer)
      vv.removeEventListener('resize', update)
      vv.removeEventListener('scroll', update)
      el.style.removeProperty('--modal-kb')
    }
  }, [el])
}

// ============================================================================
// Initial focus
// ============================================================================

const FIRST_FIELD =
  'input:not([type=hidden]):not([disabled]), textarea:not([disabled]), select:not([disabled])'

function isCoarsePointer() {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(pointer: coarse)').matches
  )
}

/**
 * Initial focus of a modal with a body, as its `onOpenAutoFocus` handler.
 * Radix would focus the first focusable element, which is the header's close
 * button. This focuses the body's first form field instead, or the body itself
 * (it has `tabIndex={-1}`) when it has none. With a coarse pointer (a phone)
 * it always focuses the body, so the on-screen keyboard does not open by
 * itself. Escape and focus return are unchanged.
 */
function focusModalBody(event: Event, body: HTMLElement | null) {
  if (!body) return
  event.preventDefault()
  const field = isCoarsePointer() ? null : body.querySelector<HTMLElement>(FIRST_FIELD)
  ;(field ?? body).focus({ preventScroll: true })
  // Caret at the end, not the whole value selected: one keystroke must not
  // replace an existing name. When a dropdown item opened the dialog, the
  // menu hands focus back to its trigger as it finishes closing and the
  // dialog's focus trap refocuses the field with everything selected, so for
  // a moment after opening every refocus puts the caret back at the end.
  if (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) {
    const caretToEnd = () => {
      if (document.activeElement !== field) return
      try {
        const end = field.value.length
        field.setSelectionRange(end, end)
      } catch {
        // number / email inputs have no selection API
      }
    }
    caretToEnd()
    const onRefocus = () => setTimeout(caretToEnd, 0)
    field.addEventListener('focus', onRefocus)
    setTimeout(() => field.removeEventListener('focus', onRefocus), 1000)
  }
}

/**
 * The `onOpenAutoFocus` of a surface's Content: the caller's handler first;
 * if it did not take over, focus the body when there is one (Radix's default
 * otherwise).
 */
function useOpenAutoFocus(
  content: React.RefObject<HTMLElement | null>,
  bodySlot: string,
  handler: ((event: Event) => void) | undefined
) {
  return React.useCallback(
    (event: Event) => {
      handler?.(event)
      if (event.defaultPrevented) return
      const body = content.current?.querySelector<HTMLElement>(`[data-slot="${bodySlot}"]`)
      focusModalBody(event, body ?? null)
    },
    [content, bodySlot, handler]
  )
}

// ============================================================================
// Parts
// ============================================================================

/**
 * The scrolling middle of a modal. Put every field, list and paragraph here;
 * never give the Content (or a wrapper) its own `max-h` / `overflow`.
 */
function ModalBody({
  slot,
  className,
  ref,
  ...props
}: React.ComponentProps<'div'> & { slot: string }) {
  const layout = useModalLayout()
  const [node, setNode] = React.useState<HTMLDivElement | null>(null)
  const setRefs = React.useCallback(
    (el: HTMLDivElement | null) => {
      setNode(el)
      if (typeof ref === 'function') ref(el)
      else if (ref) ref.current = el
    },
    [ref]
  )
  const registerBody = layout?.registerBody
  React.useLayoutEffect(() => registerBody?.(), [registerBody])
  useScrollEdges(node)
  return (
    <div
      ref={setRefs}
      data-slot={slot}
      tabIndex={-1}
      className={cn(
        'min-h-0 flex-1 overflow-y-auto overscroll-contain py-2 outline-none',
        // Last part (no footer): the bottom padding a footer would have had.
        'last:pb-[max(1rem,env(safe-area-inset-bottom))] sm:last:pb-6',
        // Dividers only while content is hidden behind the header / footer.
        'border-y border-transparent data-[overflow-top]:border-t-border data-[overflow-bottom]:border-b-border',
        SECTION_X,
        className
      )}
      {...props}
    />
  )
}

/**
 * A `<form>` that spans body and footer: it keeps the column layout so the
 * body still scrolls between header and footer, and Enter in a field submits.
 *
 *   <DialogHeader>…</DialogHeader>
 *   <ModalForm onSubmit={submit}>
 *     <DialogBody>…fields…</DialogBody>
 *     <DialogFooter><Button type="submit">Save</Button></DialogFooter>
 *   </ModalForm>
 */
function ModalForm({ className, ...props }: React.ComponentProps<'form'>) {
  return (
    <form
      data-slot="modal-form"
      className={cn('flex min-h-0 flex-1 flex-col', className)}
      {...props}
    />
  )
}

export {
  FIRST_FIELD,
  MODAL_SIZE,
  ModalBody,
  ModalForm,
  ModalLayoutContext,
  focusModalBody,
  footerSectionClass,
  headerSectionClass,
  modalSurfaceClassName,
  useKeyboardInset,
  useModalLayout,
  useModalLayoutState,
  useOpenAutoFocus,
}
export type { ModalLayout, ModalSize }
