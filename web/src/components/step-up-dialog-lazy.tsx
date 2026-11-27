'use client'

import { useEffect, useState, type ComponentType } from 'react'
import { toast } from 'sonner'

import { useTranslation } from '@/context/i18n-provider'
import { nextStepUpHandler, registerStepUpHandler } from '@/lib/api/step-up'

type Host = ComponentType

const loadHost = () => import('./step-up-dialog').then((m) => m.StepUpDialogHost as Host)

/**
 * The step-up dialog for the dashboard shell. Its code (the code input, the
 * QR code, the dialog frame) is only needed once an action answers
 * STEP_UP_REQUIRED, so it downloads then (and is fetched when the browser is
 * idle, so the dialog opens at once). Until it is there this registers a
 * placeholder that loads it, waits for it to register itself and hands the
 * prompt over; the caller sees the same promise it always did.
 *
 * If the code cannot be fetched (offline, a deploy replaced the chunk) the
 * prompt resolves false, so the action fails closed as with no dialog
 * mounted, and an error toast says why. The failed load is not kept: the next
 * attempt at the action fetches the dialog again.
 */
export function LazyStepUpDialogHost() {
  const { t } = useTranslation()
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
        toast.error(
          t(
            'components.stepUp.dialogLoadFailed',
            'Could not open the verification step. Check your connection and try again.'
          )
        )
        return false
      }
      const real = await next.ready
      return real(prompt)
    })
  }, [Host, t])

  return Host ? <Host /> : null
}
