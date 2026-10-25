/**
 * Triage mode's keys (research/234 §5.2): one key per action, every key
 * also a visible, labelled button. Keys are ignored while the person types,
 * works in a picker or menu, or has a dialog open, so a letter typed into a
 * note or a search never becomes a decision.
 */

export type TriageAction =
  | 'next'
  | 'prev'
  | 'exit'
  | 'confirm'
  | 'falsePositive'
  | 'accept'
  | 'assign'
  | 'skip'
  | 'evidence'
  | 'openPage'
  | 'help'

/** The key of each action, in the order the help lists them. */
export const TRIAGE_KEYS: ReadonlyArray<{ action: TriageAction; key: string; label: string }> = [
  { action: 'confirm', key: 'c', label: 'c' },
  { action: 'falsePositive', key: 'f', label: 'f' },
  { action: 'accept', key: 'a', label: 'a' },
  { action: 'assign', key: 'o', label: 'o' },
  { action: 'skip', key: 's', label: 's' },
  { action: 'next', key: 'j', label: 'j' },
  { action: 'prev', key: 'k', label: 'k' },
  { action: 'evidence', key: 'e', label: 'e' },
  { action: 'openPage', key: 'Enter', label: 'Enter' },
  { action: 'help', key: '?', label: '?' },
  { action: 'exit', key: 'Escape', label: 'Esc' },
]

const BY_KEY = new Map(TRIAGE_KEYS.map((k) => [k.key, k.action]))

/** Where a key belongs to the control, not to triage. */
export const TRIAGE_IGNORE_SELECTOR =
  'input, textarea, select, button, a[href], [contenteditable="true"], [contenteditable=""], [role="combobox"], [role="listbox"], [role="option"], [role="menu"], [role="menuitem"], [role="dialog"], [role="alertdialog"]'

const CLOSED_LAYER =
  '[role="dialog"][data-state="closed"], [role="alertdialog"][data-state="closed"]'
const OPEN_LAYER =
  '[role="dialog"]:not([data-state="closed"]), [role="alertdialog"]:not([data-state="closed"])'

/** Keys that still act while a button or link has focus (letters do not press it). */
const ON_CONTROLS = new Set(['j', 'k', 'c', 'f', 'a', 'o', 's', 'e', '?', 'Escape'])

export interface TriageKeyEvent {
  key: string
  metaKey?: boolean
  ctrlKey?: boolean
  altKey?: boolean
  repeat?: boolean
  defaultPrevented?: boolean
  target?: EventTarget | null
}

function closest(target: EventTarget | null | undefined, selector: string): Element | null {
  const el = target as Element | null | undefined
  return el && typeof el.closest === 'function' ? el.closest(selector) : null
}

/**
 * The action of a key press, or null when triage must leave the key alone:
 * a modifier chord, an auto-repeat, an event already handled, focus in a
 * field, picker, menu or dialog, or a dialog open anywhere on the page.
 */
export function triageActionFor(
  e: TriageKeyEvent,
  doc: Pick<Document, 'querySelector'> | null = typeof document === 'undefined' ? null : document
): TriageAction | null {
  if (e.metaKey || e.ctrlKey || e.altKey || e.repeat || e.defaultPrevented) return null
  const action = BY_KEY.get(e.key)
  if (!action) return null
  // A picker or dialog that is closing (data-state="closed", still mounted
  // for its exit animation) no longer owns the keys, even with focus inside.
  const closing = closest(e.target, CLOSED_LAYER)
  const inside = closing ? null : closest(e.target, TRIAGE_IGNORE_SELECTOR)
  if (inside) {
    // A button or link, including the closed trigger of a picker (focus
    // returns there after a pick), is not a place where letters are typed.
    const plainControl =
      (inside.tagName === 'BUTTON' || inside.tagName === 'A') &&
      inside.getAttribute('aria-expanded') !== 'true' &&
      !closest(inside, '[role="dialog"], [role="alertdialog"], [role="menu"], [role="listbox"]')
    // Enter on a button presses it; the letters still mean triage there.
    if (!plainControl || !ON_CONTROLS.has(e.key)) return null
  }
  if (doc?.querySelector(OPEN_LAYER)) return null
  return action
}
