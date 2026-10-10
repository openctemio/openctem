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
import { useTranslation } from '@/context/i18n-provider'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { isFreezeRefusal } from '@/features/scan-freeze'
import { triggerErrorHint } from '@/features/scan-zones'
import { refusedFromError, ScopeRefusalPanel, type ScopeRefusal } from '@/features/scope'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { get, post } from '@/lib/api/client'
import { scanEndpoints } from '@/lib/api/endpoints'
import { getErrorMessage } from '@/lib/api/error-handler'
import { invalidateScanConfigsCache } from '@/lib/api/scan-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'
import type { ScanRun } from '@/lib/api/scan-types'
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
async function activeRunOf(scanId: string): Promise<ScanRun | null> {
  try {
    const run = await get<ScanRun>(scanEndpoints.latestRun(scanId))
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
  const { t } = useTranslation()
  const busy = useSyncExternalStore(subscribe, getSnapshot, () => '')
  const [pending, setPending] = useState<{ scan: TriggerableScan; run: ScanRun } | null>(null)
  // A trigger refused by an active scan freeze window, offered to override
  // to members holding scans:freeze:override (the API checks it again and
  // audits the override).
  const [frozen, setFrozen] = useState<{ scan: TriggerableScan; message: string } | null>(null)
  // A trigger the scope gate refused: each target, why, and the fixes
  // (TARGET_OUT_OF_SCOPE details, RFC-054 §6.5), as in the scan dialogs.
  const [refusal, setRefusal] = useState<{ scan: TriggerableScan; refused: ScopeRefusal[] } | null>(
    null
  )
  const canOverrideFreeze = useHasPermission(Permission.ScanFreezeOverride)

  const fire = useCallback(
    async (scan: TriggerableScan, overrideFreeze = false) => {
      try {
        await post(scanEndpoints.trigger(scan.id), overrideFreeze ? { override_freeze: true } : {})
        toast.success(
          overrideFreeze
            ? t('scans.trigger.startedFrozen', undefined, { name: scan.name })
            : t('scans.trigger.triggered', undefined, { name: scan.name })
        )
        onTriggered?.(scan)
        await invalidateScanConfigsCache()
      } catch (error) {
        if (!overrideFreeze && canOverrideFreeze && isFreezeRefusal(error)) {
          // Stays in flight until the user answers.
          setFrozen({ scan, message: getErrorMessage(error, t('scans.trigger.freezeActive')) })
          return
        }
        const refused = refusedFromError(error)
        if (refused.length > 0) {
          setRefusal({ scan, refused })
          setInFlight(scan.id, false)
          return
        }
        toast.error(
          getErrorMessage(error, t('scans.trigger.failed', undefined, { name: scan.name })),
          {
            description: isFreezeRefusal(error)
              ? t('scans.trigger.freezeHint')
              : triggerErrorHint(error),
          }
        )
      }
      setInFlight(scan.id, false)
    },
    [onTriggered, canOverrideFreeze, t]
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

  const dismissFrozen = useCallback(() => {
    if (frozen) setInFlight(frozen.scan.id, false)
    setFrozen(null)
  }, [frozen])

  const progress = pending ? runTaskProgress(pending.run.task_summary, t) : null
  const started = pending?.run.started_at || pending?.run.created_at

  const freezeDialog = (
    <ConfirmDialog
      open={!!frozen}
      onOpenChange={(open) => {
        if (!open) dismissFrozen()
      }}
      title={t('scans.trigger.freezeTitle')}
      desc={
        frozen ? (
          <div className="space-y-2" data-testid="freeze-override-dialog">
            <p>{frozen.message}</p>
            <p>{t('scans.trigger.startAnywayQ', undefined, { name: frozen.scan.name })}</p>
          </div>
        ) : (
          ''
        )
      }
      confirmText={t('scans.trigger.startAnyway')}
      destructive
      handleConfirm={() => {
        const f = frozen
        setFrozen(null)
        if (f) void fire(f.scan, true)
      }}
    />
  )

  const dialog = (
    <>
      <ConfirmDialog
        open={!!pending}
        onOpenChange={(open) => {
          if (!open) dismiss()
        }}
        title={t('scans.trigger.inProgressTitle')}
        desc={
          pending ? (
            <div className="space-y-2">
              <p>
                {t('scans.trigger.hasRun', undefined, {
                  name: pending.scan.name,
                  state:
                    pending.run.status === 'pending'
                      ? t('scans.trigger.waiting')
                      : t('scans.trigger.stillRunning'),
                  started: started
                    ? t('scans.trigger.startedAt', undefined, { time: formatScanDate(started) })
                    : '',
                  progress: progress ? `, ${progress.label}` : '',
                })}
              </p>
              <p>{t('scans.trigger.sameTargets')}</p>
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
                  {t('scans.trigger.viewRunning')}
                </Button>
              )}
            </div>
          ) : (
            ''
          )
        }
        confirmText={t('scans.trigger.startAnother')}
        handleConfirm={() => {
          const p = pending
          setPending(null)
          if (p) void fire(p.scan)
        }}
      />
      {freezeDialog}
      <Dialog open={!!refusal} onOpenChange={(open) => !open && setRefusal(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {refusal ? t('scans.trigger.notStarted', undefined, { name: refusal.scan.name }) : ''}
            </DialogTitle>
            <DialogDescription>{t('scans.trigger.refusedDesc')}</DialogDescription>
          </DialogHeader>
          <DialogBody>{refusal && <ScopeRefusalPanel refused={refusal.refused} />}</DialogBody>
        </DialogContent>
      </Dialog>
    </>
  )

  return { trigger, isTriggering, dialog }
}
