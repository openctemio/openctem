'use client'

import { useEffect, useState, type ComponentType } from 'react'

import { nextStepUpHandler, registerStepUpHandler } from '@/lib/api/step-up'

type Host = ComponentType

const loadHost = () => import('./step-up-dialog').then((m) => m.StepUpDialogHost as Host)

/**
 * The step-up dialog for the dashboard shell. Its code (the code input, the
 * QR code, the dialog frame) is only needed once an action answers
 * STEP_UP_REQUIRED, so it downloads then (and is fetched when the browser is
 * idle, so the dialog opens at once). Until it is there this registers a
 * placeholder that loads it, waits for it to register itself and hands the
 * prompt over; the caller sees the same promise it always did. If the code
 * cannot be fetched the prompt resolves false, as with no dialog mounted.
 */
export function LazyStepUpDialogHost() {
  const [Host, setHost] = useState<Host | null>(null)

  useEffect(() => {
    if (Host) return
    const idle = (window as Window & { requestIdleCallback?: (cb: () => void) => number })
      .requestIdleCallback
    if (idle) idle(() => void loadHost().catch(() => {}))
    return registerStepUpHandler(async (prompt) => {
      const next = nextStepUpHandler()
      try {
        const Loaded = await loadHost()
        setHost(() => Loaded)
      } catch {
        next.stop()
        return false
      }
      const real = await next.ready
      return real(prompt)
    })
  }, [Host])

  return Host ? <Host /> : null
}
