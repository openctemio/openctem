'use client'

import { useCallback, useMemo, useState } from 'react'

/**
 * Says the outcome of a queue decision to assistive technology: one polite,
 * atomic status region per page. A toast is a visual echo that may be gone
 * before a screen reader reaches it; this region holds the last outcome.
 *
 * `announce` re-announces the same sentence twice in a row (two approvals in
 * a row read twice) by alternating a trailing no-break space.
 */
export function useQueueAnnouncer() {
  const [state, setState] = useState<{ text: string; n: number }>({ text: '', n: 0 })
  const announce = useCallback((text: string) => setState((prev) => ({ text, n: prev.n + 1 })), [])
  const region = useMemo(
    () => (
      <div
        data-slot="queue-announcer"
        role="status"
        aria-live="polite"
        aria-atomic="true"
        className="sr-only"
      >
        {state.text ? `${state.text}${state.n % 2 ? '' : ' '}` : ''}
      </div>
    ),
    [state]
  )
  return { announce, region }
}
