/**
 * The input modality of the page: `data-input="keyboard"` or `"pointer"` on
 * `<html>`, after the last key press or pointer press.
 *
 * Why: a focus ring is for keyboard users. Browsers decide `:focus-visible`
 * by heuristics that show the ring at rest after a pointer action when the
 * focus is moved by script: a sheet that focuses the current page's row on
 * open, a menu or select that gives the focus back to its trigger on close, a
 * list that focuses its panel after a click. A mouse user then sees the
 * keyboard ring on a control they never tabbed to.
 *
 * The `focus-visible:` variant of the theme (`src/app/globals.css`) is gated
 * on this attribute: under `pointer` no control except a text field draws a
 * focus ring (a text field keeps it: it shows where typing goes). One key
 * press (Tab, an arrow, Enter, Escape) switches back to `keyboard` before the
 * focus moves, so keyboard users see the ring at once. Key chords with Ctrl,
 * Alt or Cmd (copy, the browser's own shortcuts) and modifier keys pressed
 * alone do not count, as in the browsers' own heuristic.
 *
 * Installed once for the app and the console (`src/app/providers.tsx`). Until
 * it runs the browser's own `:focus-visible` applies.
 */

export type InputModality = 'keyboard' | 'pointer'

export const INPUT_MODALITY_ATTRIBUTE = 'data-input'

const MODIFIER_KEYS = new Set(['Shift', 'Control', 'Alt', 'Meta', 'CapsLock', 'Fn', 'AltGraph'])

/** Whether a key press makes the page keyboard-driven. */
export function isNavigationKey(
  event: Pick<KeyboardEvent, 'key' | 'metaKey' | 'ctrlKey' | 'altKey'>
) {
  if (event.metaKey || event.ctrlKey || event.altKey) return false
  return !MODIFIER_KEYS.has(event.key)
}

function set(root: HTMLElement, modality: InputModality) {
  if (root.getAttribute(INPUT_MODALITY_ATTRIBUTE) !== modality) {
    root.setAttribute(INPUT_MODALITY_ATTRIBUTE, modality)
  }
}

let installed: (() => void) | null = null

/**
 * Starts tracking the modality on `document.documentElement` and returns the
 * cleanup. Idempotent: a second call while installed does nothing more.
 */
export function installInputModality(doc: Document = document): () => void {
  if (installed) return installed
  const root = doc.documentElement
  const win = doc.defaultView
  if (!win) return () => {}
  // Nothing pressed yet: the page was opened or reloaded, most often with a
  // pointer. The first key press switches to keyboard before its focus move.
  if (!root.hasAttribute(INPUT_MODALITY_ATTRIBUTE)) set(root, 'pointer')
  const onKey = (event: KeyboardEvent) => {
    if (isNavigationKey(event)) set(root, 'keyboard')
  }
  const onPointer = () => set(root, 'pointer')
  // Capture phase: a component that stops the event (a menu, a sheet) still
  // tells the page how it was driven.
  win.addEventListener('keydown', onKey, true)
  win.addEventListener('pointerdown', onPointer, true)
  const cleanup = () => {
    win.removeEventListener('keydown', onKey, true)
    win.removeEventListener('pointerdown', onPointer, true)
    installed = null
  }
  installed = cleanup
  return cleanup
}
