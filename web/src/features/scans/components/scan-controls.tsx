'use client'

import { useState } from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Loader2, Pause, Play, Power } from 'lucide-react'
import { toast } from 'sonner'

import { Button } from '@/components/ui/button'
import { post } from '@/lib/api/client'
import { scanEndpoints } from '@/lib/api/endpoints'
import { getErrorMessage } from '@/lib/api/error-handler'
import { invalidateScanConfigsCache } from '@/lib/api/scan-hooks'
import type { ScanConfig } from '@/lib/api/scan-types'
import { Can, Permission } from '@/lib/permissions'
import { useScanTrigger } from '../hooks/use-scan-trigger'
import { hasSchedule, scheduleOn } from '../lib/scan-status'
import { enTranslate, type Translate } from '../lib/translate'

/**
 * A scan's run and schedule controls, the same on the scan page and in the
 * scan drawer:
 *
 * - Run now: any enabled scan, paused or not (pausing turns the schedule
 *   off; it does not stop a person running the scan). Needs scans:write and
 *   scans:execute, as the API does.
 * - Schedule on / off: only a scan with a schedule. A manual scan has no
 *   schedule to switch.
 * - Enable: a disabled scan, which runs for nobody.
 */
export function ScanControls({
  config,
  onViewRun,
  onChanged,
}: {
  config: ScanConfig
  onViewRun?: (runId: string) => void
  onChanged?: () => void
}) {
  const { t } = useTranslation()
  const [busy, setBusy] = useState(false)
  const { trigger, isTriggering, dialog } = useScanTrigger({
    onViewRun,
    onTriggered: onChanged,
  })
  const triggering = isTriggering(config.id)

  const setState = async (action: 'pause' | 'activate', done: string) => {
    setBusy(true)
    try {
      await post(
        action === 'pause' ? scanEndpoints.pause(config.id) : scanEndpoints.activate(config.id),
        {}
      )
      toast.success(done)
      await invalidateScanConfigsCache()
      onChanged?.()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('scans.controls.updateFailed', undefined, { name: config.name }))
      )
    } finally {
      setBusy(false)
    }
  }

  if (config.status === 'disabled') {
    return (
      <Can permission={Permission.ScansWrite} mode="disable">
        <Button
          size="sm"
          onClick={() =>
            void setState('activate', t('scans.controls.enabled', undefined, { name: config.name }))
          }
          disabled={busy}
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Power className="h-4 w-4" />}
          {t('scans.controls.enable')}
        </Button>
      </Can>
    )
  }

  const on = scheduleOn(config)
  return (
    <>
      <Can permission={[Permission.ScansWrite, Permission.ScansExecute]} requireAll mode="disable">
        <Button
          size="sm"
          onClick={() => void trigger(config)}
          disabled={triggering || busy}
          aria-busy={triggering}
        >
          {triggering ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
          {t('scans.controls.runNow')}
        </Button>
      </Can>
      {hasSchedule(config) && (
        <Can permission={Permission.ScansWrite} mode="disable">
          <Button
            size="sm"
            variant="outline"
            onClick={() =>
              void setState(
                on ? 'pause' : 'activate',
                t(on ? 'scans.controls.scheduleOff' : 'scans.controls.scheduleOn', undefined, {
                  name: config.name,
                })
              )
            }
            disabled={busy || triggering}
          >
            {busy ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : on ? (
              <Pause className="h-4 w-4" />
            ) : (
              <Play className="h-4 w-4" />
            )}
            {on ? t('scans.state.scheduleOff') : t('scans.state.scheduleOn')}
          </Button>
        </Can>
      )}
      {dialog}
    </>
  )
}

/**
 * The configuration's state in words, for headers: never a run state.
 * Manual scans: "Manual" (or "Disabled"). Scheduled: "Schedule on/off".
 */
export function scanStateLabel(
  config: Pick<ScanConfig, 'status' | 'schedule_type'>,
  t: Translate = enTranslate
): string {
  if (config.status === 'disabled') return t('scans.state.disabled')
  if (!hasSchedule(config)) return t('scans.state.manual')
  return scheduleOn(config) ? t('scans.state.scheduleOn') : t('scans.state.scheduleOff')
}
