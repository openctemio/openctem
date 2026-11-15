/**
 * Where focus goes when a floating surface (popover, picker, sheet, dialog)
 * opens on a touch screen.
 *
 * Focusing a text field opens the on-screen keyboard, which covers half of a
 * phone screen before the user has even seen the options. So on a touch
 * screen a surface never focuses a text field on open: focus goes to the
 * surface itself (its option list when it has one, with the first option
 * active, so Enter and the arrow keys of an attached keyboard still work),
 * and the keyboard opens when the user taps the field. With a mouse or
 * trackpad the field gets focus on open, as before.
 *
 * The exceptions, surfaces whose one purpose is typing, are listed in
 * `TOUCH_TYPING_SURFACES` and nowhere else; a surface opts in with its
 * `typingSurface` prop. The rule is listed in `web/docs/ui-style-contract.md`
 * ("Floating surfaces").
 */
import * as React from 'react'

/**
 * Surfaces that focus their text field on open on a touch screen too, each
 * with the reason. Add an entry only for a surface that has nothing to do
 * but type.
 */
export const TOUCH_TYPING_SURFACES = {
  /** The search and command palettes: opening one means typing in it. */
  'command-menu': 1,
  /** The password, code or reason that confirms a sensitive action. */
  'step-up': 1,
  /** Typing a name to confirm a destructive action. */
  'type-to-confirm': 1,
  /** A surface that asks for one value only: a new name, a label. */
  'single-field': 1,
} as const

export type TouchTypingSurface = keyof typeof TOUCH_TYPING_SURFACES

const TOUCH_QUERY = '(pointer: coarse) and (hover: none)'

/**
 * Whether the primary input is a finger: a coarse pointer that cannot hover
 * (a phone or a tablet without a trackpad). A tablet with a trackpad or a
 * mouse reports a fine pointer and keeps the desktop behaviour.
 */
export function isTouchPrimary(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia(TOUCH_QUERY).matches
  )
}

/** Whether a surface may focus a text field when it opens. */
export function opensWithTextFocus(typingSurface?: TouchTypingSurface): boolean {
  return !isTouchPrimary() || !!(typingSurface && TOUCH_TYPING_SURFACES[typingSurface])
}

const NOT_TEXT = /^(checkbox|radio|button|submit|reset|range|color|file|hidden|image)$/

/** Whether `el` is a field that brings up the on-screen keyboard. */
export function isTextEntry(el: Element | null): boolean {
  return (
    el instanceof HTMLTextAreaElement ||
    (el instanceof HTMLInputElement && !NOT_TEXT.test(el.type)) ||
    (el instanceof HTMLElement && el.isContentEditable)
  )
}

/**
 * Moves focus to the surface instead of its text field: the option list when
 * there is one (a `Command` list is a listbox whose active descendant is the
 * highlighted option), otherwise the surface itself.
 */
export function focusSurface(surface: HTMLElement): void {
  const list = surface.querySelector<HTMLElement>('[data-slot="command-list"]')
  const target = list ?? surface
  if (!target.hasAttribute('tabindex')) target.tabIndex = -1
  if (list && !list.getAttribute('aria-activedescendant')) {
    // The list highlights its first option before any key is pressed but
    // names it as active only once one is: name it now, so a screen reader
    // announces the option Enter would pick.
    const active = list.querySelector<HTMLElement>('[cmdk-item][data-selected="true"]')
    if (active?.id) list.setAttribute('aria-activedescendant', active.id)
  }
  target.focus({ preventScroll: true })
}

/**
 * The `onOpenAutoFocus` step every kit surface runs after the caller's own
 * handler: on a touch screen, when the surface holds a text field, it
 * focuses the surface instead of letting the focus trap pick the first
 * focusable element. Returns whether it took over.
 */
export function redirectOpenFocus(
  event: Event,
  surface: HTMLElement | null,
  typingSurface?: TouchTypingSurface
): boolean {
  if (event.defaultPrevented || !surface || opensWithTextFocus(typingSurface)) return false
  if (!Array.from(surface.querySelectorAll('input,textarea,[contenteditable]')).some(isTextEntry))
    return false
  event.preventDefault()
  focusSurface(surface)
  return true
}

type FocusScope = {
  typingSurface: TouchTypingSurface | undefined
  /** Set once the surface has opened: a field mounted after that came from a user action. */
  opened: React.RefObject<boolean>
}

const FloatingFocusContext = React.createContext<FocusScope | null>(null)

/**
 * Marks the content of a floating surface, so a kit field inside it knows
 * whether its `autoFocus` may open the keyboard. Every kit surface wraps its
 * children in it.
 */
export function FloatingFocusScope({
  typingSurface,
  children,
}: {
  typingSurface?: TouchTypingSurface
  children?: React.ReactNode
}) {
  const opened = React.useRef(false)
  React.useEffect(() => {
    opened.current = true
  }, [])
  const value = React.useMemo(() => ({ typingSurface, opened }), [typingSurface])
  return React.createElement(FloatingFocusContext.Provider, { value }, children)
}

/**
 * The `autoFocus` a kit field (Input, Textarea, Command search) passes on.
 * Inside a floating surface on a touch screen, a field that appears as the
 * surface opens loses it, unless the surface is a typing surface. A field
 * that appears later, after a tap inside the open surface (Edit name, a
 * picked filter field), keeps it: the user asked for it. Outside a surface it
 * is left as it is.
 */
export function useSurfaceAutoFocus(autoFocus: boolean | undefined): boolean | undefined {
  const scope = React.useContext(FloatingFocusContext)
  // Read once, when the field mounts: did it come with the surface?
  const [withSurface] = React.useState(() => !!scope && !scope.opened.current)
  if (!autoFocus || !withSurface || !scope) return autoFocus
  return opensWithTextFocus(scope.typingSurface)
}
