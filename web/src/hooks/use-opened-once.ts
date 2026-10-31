'use client'

import { useState } from 'react'

/**
 * True from the first time `open` is true, for good. A dialog loaded on
 * demand (next/dynamic) renders only once this is true, so its code downloads
 * when it is first opened instead of with the page, and stays mounted after
 * closing so the exit animation plays and reopening is instant.
 */
export function useOpenedOnce(open: boolean): boolean {
  const [opened, setOpened] = useState(open)
  // Derived state, set during render (no extra commit, no flash of nothing).
  if (open && !opened) setOpened(true)
  return opened || open
}
