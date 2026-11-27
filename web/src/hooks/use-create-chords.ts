'use client'

import { useEffect, useLayoutEffect, useRef } from 'react'
import { CREATE_ACTION_DEFS, type CreateAction } from './use-create-actions'

/**
 * The first key of every create chord. Free on every page: the page keys
 * are / a c d e f j k m o r s t u x ? (src/config/keyboard-shortcuts.ts and
 * the triage keys); "c" belongs to the activity panel and triage.
 */
export const CREATE_PREFIX = 'n'

/** How long after the prefix the second key still counts as the chord. */
export const CHORD_WINDOW_MS = 1000

/** Every chord letter, allowed or not: "n t" must never reach a page as "t". */
const CHORD_KEYS: ReadonlySet<string> = new Set(
  CREATE_ACTION_DEFS.flatMap((d) => (d.chord ? [d.chord] : []))
)

function isTyping(target: EventTarget | null): boolean {
  const el = target as HTMLElement | null
  if (!el || typeof el.closest !== 'function') return false
  return (
    el.isContentEditable ||
    el.tagName === 'INPUT' ||
    el.tagName === 'TEXTAREA' ||
    el.tagName === 'SELECT' ||
    !!el.closest('[role="dialog"],[role="menu"],[role="listbox"],[role="combobox"]')
  )
}

const plain = (e: KeyboardEvent) => !e.metaKey && !e.ctrlKey && !e.altKey && !e.shiftKey

/**
 * The Create chords: "n" then a letter within a second runs that create
 * action (n s scan, n i import, n a asset, n f finding, n t task), on every
 * page of the app (the listener lives in the header, which every page has).
 *
 * - No page binds "n"; should one ever take it (preventDefault on `document`,
 *   which runs before this `window` listener), the page wins.
 * - While a chord is pending, its second key is caught in the capture phase
 *   on `window`, before any page shortcut (t, f, a, s, ...) sees it.
 * - Typing in a field, a dialog, a menu or a list box never starts a chord.
 */
export function useCreateChords(actions: CreateAction[], run: (action: CreateAction) => void) {
  const latest = useRef({ actions, run })
  useLayoutEffect(() => {
    latest.current = { actions, run }
  })

  useEffect(() => {
    let pendingUntil = 0

    const onCapture = (e: KeyboardEvent) => {
      if (!pendingUntil) return
      if (e.key === 'Shift' || e.key === 'Control' || e.key === 'Alt' || e.key === 'Meta') return
      const live = Date.now() <= pendingUntil
      pendingUntil = 0
      if (!live || !plain(e) || isTyping(e.target)) return
      const key = e.key.toLowerCase()
      if (!CHORD_KEYS.has(key)) return
      e.preventDefault()
      e.stopImmediatePropagation()
      const action = latest.current.actions.find((a) => a.chord === key)
      if (action) latest.current.run(action)
    }

    const onBubble = (e: KeyboardEvent) => {
      if (e.key !== CREATE_PREFIX || !plain(e) || e.defaultPrevented || e.repeat) return
      if (isTyping(e.target)) return
      pendingUntil = Date.now() + CHORD_WINDOW_MS
    }

    window.addEventListener('keydown', onCapture, true)
    window.addEventListener('keydown', onBubble)
    return () => {
      window.removeEventListener('keydown', onCapture, true)
      window.removeEventListener('keydown', onBubble)
    }
  }, [])
}
