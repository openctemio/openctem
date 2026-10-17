import type { MouseEvent } from 'react'

/**
 * True for an unmodified primary-button click. Anything else (ctrl/cmd/shift/alt
 * or a non-primary button) is the browser's own "open in a new tab/window"
 * gesture and must be left alone.
 */
export function isPlainLeftClick(
  e: Pick<MouseEvent, 'button' | 'metaKey' | 'ctrlKey' | 'shiftKey' | 'altKey' | 'defaultPrevented'>
): boolean {
  return (
    !e.defaultPrevented && e.button === 0 && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey
  )
}
