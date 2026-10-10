'use client'

import * as React from 'react'
import { useTranslation } from '@/context/i18n-provider'
import { Clock, Loader2 } from 'lucide-react'
import { Switch } from '@/components/ui/switch'
import type { ScanConfig } from '@/lib/api/scan-types'
import { scheduleTypeName } from '../lib/labels'
import { enTranslate, type Translate } from '../lib/translate'
import { Permission, useHasPermission } from '@/lib/permissions'
import { hasSchedule, scheduleOn } from '../lib/scan-status'

/** "in 2 days", "in 3 hours", "Soon", "Overdue"; null without a date. */
export function formatNextRun(
  nextRunAt?: string,
  now: number = Date.now(),
  t: Translate = enTranslate
): string | null {
  if (!nextRunAt) return null
  const diffMs = new Date(nextRunAt).getTime() - now
  if (!Number.isFinite(diffMs)) return null
  if (diffMs < 0) return t('scans.nextRun.overdue')
  const minutes = Math.floor(diffMs / 60000)
  const hours = Math.floor(minutes / 60)
  const days = Math.floor(hours / 24)
  if (days > 0) {
    return t(days > 1 ? 'scans.nextRun.inDayMany' : 'scans.nextRun.inDayOne', undefined, {
      count: days,
    })
  }
  if (hours > 0) {
    return t(hours > 1 ? 'scans.nextRun.inHourMany' : 'scans.nextRun.inHourOne', undefined, {
      count: hours,
    })
  }
  if (minutes > 0) {
    return t(minutes > 1 ? 'scans.nextRun.inMinMany' : 'scans.nextRun.inMinOne', undefined, {
      count: minutes,
    })
  }
  return t('scans.nextRun.soon')
}

/**
 * The Schedule column: the schedule, its next run, and the switch that turns
 * the schedule on or off (pause / resume). A manual scan has no schedule and
 * so no switch: it runs only when someone runs it, paused or not. A disabled
 * scan shows the switch off and locked (enable it from its page).
 */
export function ScheduleCell({
  config,
  onToggle,
}: {
  config: ScanConfig
  onToggle: (action: 'pause' | 'activate', config: ScanConfig) => Promise<void>
}) {
  const { t } = useTranslation()
  const canWrite = useHasPermission(Permission.ScansWrite)
  const [saving, setSaving] = React.useState(false)
  const [on, setOn] = React.useState(scheduleOn(config))
  React.useEffect(() => setOn(scheduleOn(config)), [config])

  if (!hasSchedule(config)) {
    return <span className="text-sm text-muted-foreground">{t('scans.state.manual')}</span>
  }

  const disabled = config.status === 'disabled'
  const nextRun = on ? formatNextRun(config.next_run_at, undefined, t) : null
  const toggle = async (checked: boolean) => {
    if (saving || disabled) return
    setOn(checked)
    setSaving(true)
    try {
      await onToggle(checked ? 'activate' : 'pause', config)
    } catch {
      setOn(scheduleOn(config))
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex items-center gap-2">
      <div className="relative">
        <Switch
          checked={on}
          onCheckedChange={toggle}
          disabled={disabled || saving || !canWrite}
          aria-label={on ? t('scans.cell.scheduleOffAria') : t('scans.cell.scheduleOnAria')}
        />
        {saving && (
          <span className="absolute inset-0 flex items-center justify-center">
            <Loader2 className="h-3 w-3 animate-spin text-muted-foreground motion-reduce:animate-none" />
          </span>
        )}
      </div>
      <div className="flex min-w-0 flex-col">
        <span className="text-sm">{scheduleTypeName(t, config.schedule_type)}</span>
        <span className="flex items-center gap-1 text-xs text-muted-foreground">
          {disabled ? (
            t('scans.state.disabled')
          ) : on ? (
            nextRun ? (
              <>
                <Clock className="h-3 w-3" />
                {t('scans.cell.next', undefined, { time: nextRun })}
              </>
            ) : (
              t('scans.state.scheduleOn')
            )
          ) : (
            t('scans.state.scheduleOff')
          )}
        </span>
      </div>
    </div>
  )
}
