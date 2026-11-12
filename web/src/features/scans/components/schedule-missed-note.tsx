'use client'

import { Loader2, Play } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import type { ScanConfig } from '@/lib/api/scan-types'
import { Can, Permission } from '@/lib/permissions'
import { useScanTrigger } from '../hooks/use-scan-trigger'
import { formatScanDate } from '../lib/format'
import { hasScheduleMissed, missedReasonLabel } from '../lib/schedule-missed'
import { isManagedScan } from '../lib/scan-status'

/**
 * "Missed <time>: <reason>" next to a scan's Next run, with [Run now]: the
 * scheduler skipped an occurrence that was more than one interval late. The
 * button is the scan's own Run now (same endpoint, same permissions), and the
 * note goes away once a later scheduled run starts.
 */
export function ScheduleMissedNote({
  config,
  onChanged,
  onViewRun,
  showRunNow = true,
}: {
  config: ScanConfig
  onChanged?: () => void
  onViewRun?: (runId: string) => void
  showRunNow?: boolean
}) {
  const { t } = useTranslation()
  if (!hasScheduleMissed(config) || !config.last_missed_at) return null
  const text = (
    <span>
      {t('scans.missed.note', undefined, {
        time: formatScanDate(config.last_missed_at),
        reason: missedReasonLabel(config.last_missed_reason, t),
      })}
    </span>
  )
  const canRun = showRunNow && !isManagedScan(config)
  return (
    <span className="inline-flex flex-wrap items-center gap-2 text-sm text-warning">
      {text}
      {canRun && <MissedRunNow config={config} onChanged={onChanged} onViewRun={onViewRun} />}
    </span>
  )
}

/** The [Run now] of the note: the scan's own trigger, same permissions. */
function MissedRunNow({
  config,
  onChanged,
  onViewRun,
}: {
  config: ScanConfig
  onChanged?: () => void
  onViewRun?: (runId: string) => void
}) {
  const { t } = useTranslation()
  const { trigger, isTriggering, dialog } = useScanTrigger({ onViewRun, onSettled: onChanged })
  const triggering = isTriggering(config.id)
  return (
    <>
      <Can permission={[Permission.ScansWrite, Permission.ScansExecute]} requireAll mode="disable">
        <Button
          size="sm"
          variant="outline"
          onClick={() => void trigger(config)}
          disabled={triggering}
          aria-busy={triggering}
        >
          {triggering ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
          {t('scans.controls.runNow')}
        </Button>
      </Can>
      {dialog}
    </>
  )
}
