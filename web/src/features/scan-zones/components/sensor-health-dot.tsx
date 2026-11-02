'use client'

import { useTranslation } from '@/context/i18n-provider'
import { cn } from '@/lib/utils'
import type { Sensor } from '@/lib/api/sensor-types'
import type { SensorStateTone } from '@/features/sensors/lib/sensor-state'

import {
  isSensorHealthy,
  sensorStateLabel,
  sensorStateTone,
  type ZoneSensorStateInput,
} from '../lib/sensor-health'

const FILLED: Record<SensorStateTone, string> = {
  success: 'bg-success',
  warning: 'bg-warning',
  destructive: 'bg-destructive',
  info: 'bg-info',
  muted: 'bg-muted-foreground',
}

const HOLLOW: Record<SensorStateTone, string> = {
  success: 'border border-success',
  warning: 'border border-warning',
  destructive: 'border border-destructive',
  info: 'border border-info',
  muted: 'border border-muted-foreground',
}

/**
 * A sensor's name with its state: a filled dot when it can take jobs (the
 * stored health, as the router sees it), coloured by the state shown on the
 * Sensors tab.
 */
export function SensorHealthChip({
  sensor,
  className,
}: {
  sensor: Pick<Sensor, 'name'> & ZoneSensorStateInput
  className?: string
}) {
  const { t } = useTranslation()
  const healthy = isSensorHealthy(sensor)
  const label = sensorStateLabel(sensor, t)
  const tone = sensorStateTone(sensor)
  return (
    <span
      className={cn(
        'inline-flex max-w-full items-center gap-1.5 rounded-md border px-1.5 py-0.5 text-xs',
        className
      )}
      title={`${sensor.name}: ${label}`}
    >
      <span
        aria-hidden
        className={cn('h-2 w-2 shrink-0 rounded-full', healthy ? FILLED[tone] : HOLLOW[tone])}
      />
      <span className="truncate">{sensor.name}</span>
      <span className="sr-only">({label})</span>
    </span>
  )
}
