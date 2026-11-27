'use client'

// Kept apart from keyboard-shortcuts-dialog.tsx: the sidebar shows key caps at
// once, while the dialog (and the shortcut list) loads when it first opens.

import { Fragment, useSyncExternalStore } from 'react'
import type { ShortcutKey } from '@/config/keyboard-shortcuts'

const subscribeNoop = () => () => {}

/** macOS / iOS show Cmd and the Shift glyph; everything else Ctrl and Shift. */
function useIsApple(): boolean {
  return useSyncExternalStore(
    subscribeNoop,
    () => /Mac|iPhone|iPad|iPod/i.test(navigator.userAgent),
    () => false
  )
}

function keyLabel(key: ShortcutKey, apple: boolean): string {
  if (key === 'mod') return apple ? '⌘' : 'Ctrl'
  if (key === 'shift') return apple ? '⇧' : 'Shift'
  if (key === 'esc') return 'Esc'
  return key
}

/** One key cap, the same look as the ⌘K hint on the search button. */
function Kbd({ children }: { children: string }) {
  return (
    <kbd className="inline-flex h-6 min-w-6 items-center justify-center rounded border bg-muted px-1.5 font-sans text-xs font-medium text-muted-foreground">
      {children}
    </kbd>
  )
}

export function ShortcutKeys({
  keys,
  sequence,
  thenLabel = 'then',
}: {
  keys: ShortcutKey[]
  /** Pressed one after the other: the caps are joined by `thenLabel`. */
  sequence?: boolean
  thenLabel?: string
}) {
  const apple = useIsApple()
  return (
    <span className="flex shrink-0 items-center gap-1" dir="ltr">
      {keys.map((k, i) => (
        <Fragment key={k}>
          {i > 0 && sequence && <span className="text-cap text-muted-foreground">{thenLabel}</span>}
          {i > 0 && !sequence && !apple && (
            <span className="text-cap text-muted-foreground">+</span>
          )}
          <Kbd>{keyLabel(k, apple)}</Kbd>
        </Fragment>
      ))}
    </span>
  )
}
