'use client'

/**
 * The one way to trigger a scan from the web (research 20 §4.2a, G19).
 *
 * Live use showed two "Trigger" clicks 12 s apart creating a second manual
 * run while the first was still running on the same host. Every Trigger
 * button (list row menu, scan drawer, scan page) now goes through this hook:
 *
 * - a second click on the same scan while its trigger is in flight is
 *   ignored, across every button on the page (the in-flight set is shared);
 * - before posting, the scan's latest run is read; if it is still pending or
 *   running the user is asked whether to start another run, with the run's
 *   progress and a way to open it, instead of a silent duplicate.
 *
 * A second manual run stays allowed (owner decision D4 skips only scheduled
 * overlaps); this is a guard for people, not an authorization rule. The
 * backend remains the authority on who may trigger (scans:write +
 * scans:execute).
 */

import { useCallback, useState, useSyncExternalStore } from 'react'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { triggerErrorHint } from '@/features/scan-zones'
import { get, post } from '@/lib/api/client'
import { scanEndpoints } from '@/lib/api/endpoints'
import { getErrorMessage } from '@/lib/api/error-handler'
import { invalidateScanConfigsCache } from '@/lib/api/scan-hooks'
import type { PipelineRun } from '@/lib/api/scan-types'
import { formatScanDate } from '../lib/format'
import { isRunInProgress, runTaskProgress } from '../lib/run-display'

export interface TriggerableScan {
  id: string
  name: string
}

// Scans whose trigger is in flight, shared by every hook instance so the
// drawer and the page cannot both fire for one scan.
const inFlight = new Set<string>()
const listeners = new Set<() => void>()
function emit() {
  for (const l of listeners) l()
}
function subscribe(l: () => void) {
  listeners.add(l)
  return () => {
    listeners.delete(l)
  }
}
let snapshot = ''
function getSnapshot() {
  return snapshot
}
function setInFlight(id: string, on: boolean) {
  if (on) inFlight.add(id)
  else inFlight.delete(id)
  snapshot = [...inFlight].sort().join(',')
  emit()
}

/** Test seam: forget every in-flight trigger. */
export function resetScanTriggerStateForTests() {
  inFlight.clear()
  snapshot = ''
  emit()
}

function isNotFound(err: unknown): boolean {
  return (
    typeof err === 'object' && err !== null && (err as { statusCode?: unknown }).statusCode === 404
  )
}

/** The scan's latest run when it is still pending or running, else null. */
async function activeRunOf(scanId: string): Promise<PipelineRun | null> {
  try {
    const run = await get<PipelineRun>(scanEndpoints.latestRun(scanId))
    return run && isRunInProgress(run) ? run : null
  } catch (err) {
    // No run yet is a 404. Any other failure must not block the trigger:
    // the check is a convenience, and the trigger itself still reports errors.
    if (!isNotFound(err)) console.warn('latest run check failed', err)
    return null
  }
}

export interface UseScanTriggerOptions {
  /** Called after a run was started. */
  onTriggered?: (scan: TriggerableScan) => void
  /** Offered in the "already running" dialog to open the active run. */
  onViewRun?: (runId: string) => void
}

export function useScanTrigger({ onTriggered, onViewRun }: UseScanTriggerOptions = {}) {
  const busy = useSyncExternalStore(subscribe, getSnapshot, () => '')
  const [pending, setPending] = useState<{ scan: TriggerableScan; run: PipelineRun } | null>(null)

  const fire = useCallback(
    async (scan: TriggerableScan) => {
      try {
        await post(scanEndpoints.trigger(scan.id), {})
        toast.success(`Scan "${scan.name}" triggered`)
        onTriggered?.(scan)
        await invalidateScanConfigsCache()
      } catch (error) {
        toast.error(getErrorMessage(error, `Failed to trigger scan "${scan.name}"`), {
          description: triggerErrorHint(error),
        })
      } finally {
        setInFlight(scan.id, false)
      }
    },
    [onTriggered]
  )

  const trigger = useCallback(
    async (scan: TriggerableScan) => {
      if (inFlight.has(scan.id)) return
      setInFlight(scan.id, true)
      const active = await activeRunOf(scan.id)
      if (active) {
        // Stays in flight until the user answers.
        setPending({ scan, run: active })
        return
      }
      await fire(scan)
    },
    [fire]
  )

  const isTriggering = useCallback((scanId: string) => busy.split(',').includes(scanId), [busy])

  const dismiss = useCallback(() => {
    if (pending) setInFlight(pending.scan.id, false)
    setPending(null)
  }, [pending])

  const progress = pending ? runTaskProgress(pending.run.task_summary) : null
  const started = pending?.run.started_at || pending?.run.created_at

  const dialog = (
    <ConfirmDialog
      open={!!pending}
      onOpenChange={(open) => {
        if (!open) dismiss()
      }}
      title="A run is already in progress"
      desc={
        pending ? (
          <div className="space-y-2">
            <p>
              <span className="font-medium text-foreground">{pending.scan.name}</span> has a run
              that is {pending.run.status === 'pending' ? 'waiting to start' : 'still running'}
              {started ? ` (started ${formatScanDate(started)})` : ''}
              {progress ? `, ${progress.label}` : ''}.
            </p>
            <p>
              Another run scans the same targets again; the sensor runs them one after the other.
            </p>
            {onViewRun && (
              <Button
                variant="link"
                className="h-auto p-0"
                onClick={() => {
                  const runId = pending.run.id
                  dismiss()
                  onViewRun(runId)
                }}
              >
                View the running run
              </Button>
            )}
          </div>
        ) : (
          ''
        )
      }
      confirmText="Start another run"
      handleConfirm={() => {
        const p = pending
        setPending(null)
        if (p) void fire(p.scan)
      }}
    />
  )

  return { trigger, isTriggering, dialog }
}
