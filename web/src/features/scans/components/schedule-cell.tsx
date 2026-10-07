'use client'

import * as React from 'react'
import { Clock, Loader2 } from 'lucide-react'
import { Switch } from '@/components/ui/switch'
import { SCHEDULE_TYPE_LABELS, type ScanConfig } from '@/lib/api/scan-types'
import { Permission, useHasPermission } from '@/lib/permissions'
import { hasSchedule, scheduleOn } from '../lib/scan-status'

/** "in 2 days", "in 3 hours", "Soon", "Overdue"; null without a date. */
export function formatNextRun(nextRunAt?: string, now: number = Date.now()): string | null {
  if (!nextRunAt) return null
  const diffMs = new Date(nextRunAt).getTime() - now
  if (!Number.isFinite(diffMs)) return null
  if (diffMs < 0) return 'Overdue'
  const minutes = Math.floor(diffMs / 60000)
  const hours = Math.floor(minutes / 60)
  const days = Math.floor(hours / 24)
  if (days > 0) return `in ${days} day${days > 1 ? 's' : ''}`
  if (hours > 0) return `in ${hours} hour${hours > 1 ? 's' : ''}`
  if (minutes > 0) return `in ${minutes} min${minutes > 1 ? 's' : ''}`
  return 'Soon'
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
  const canWrite = useHasPermission(Permission.ScansWrite)
  const [saving, setSaving] = React.useState(false)
  const [on, setOn] = React.useState(scheduleOn(config))
  React.useEffect(() => setOn(scheduleOn(config)), [config])

  if (!hasSchedule(config)) {
    return <span className="text-sm text-muted-foreground">Manual</span>
  }

  const disabled = config.status === 'disabled'
  const nextRun = on ? formatNextRun(config.next_run_at) : null
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
          aria-label={on ? 'Turn the schedule off' : 'Turn the schedule on'}
        />
        {saving && (
          <span className="absolute inset-0 flex items-center justify-center">
            <Loader2 className="h-3 w-3 animate-spin text-muted-foreground motion-reduce:animate-none" />
          </span>
        )}
      </div>
      <div className="flex min-w-0 flex-col">
        <span className="text-sm">{SCHEDULE_TYPE_LABELS[config.schedule_type]}</span>
        <span className="flex items-center gap-1 text-xs text-muted-foreground">
          {disabled ? (
            'Disabled'
          ) : on ? (
            nextRun ? (
              <>
                <Clock className="h-3 w-3" />
                Next: {nextRun}
              </>
            ) : (
              'Schedule on'
            )
          ) : (
            'Schedule off'
          )}
        </span>
      </div>
    </div>
  )
}
