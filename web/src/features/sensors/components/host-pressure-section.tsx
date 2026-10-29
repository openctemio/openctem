'use client'

import { TriangleAlert } from 'lucide-react'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import { DetailField, DetailFieldGrid, DetailSection } from '@/features/shared'
import type { Sensor } from '@/lib/api/sensor-types'

import { formatDurationShort } from '../lib/format'

/** The reason tokens the API keeps (api pkg/domain/sensor/load.go). */
const KNOWN_REASONS = new Set(['cpu', 'memory', 'io', 'load', 'mem_available', 'fds'])

function pct(v: number): string {
  return `${Number.isInteger(v) ? v : v.toFixed(1)}%`
}

/**
 * The sensor host's pressure as the sensor last reported it (api
 * research/318): the level, why, how much the host stalls on CPU, memory and
 * disk, and the start problems the sensor absorbed. Nothing when the sensor
 * reports none (an older sensor).
 */
export function HostPressureSection({ sensor }: { sensor: Pick<Sensor, 'load'> }) {
  const { t } = useTranslation()
  const p = sensor.load?.resources?.pressure
  if (!p) return null
  const cap = sensor.load?.capacity
  const tr = cap?.transient
  const level = p.level === 'elevated' || p.level === 'overloaded' ? p.level : 'ok'
  const reasons = (p.reasons ?? []).filter((r) => KNOWN_REASONS.has(r))
  return (
    <DetailSection title={t('sensors.pressure.title')}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge
          variant={
            level === 'overloaded' ? 'destructive' : level === 'elevated' ? 'default' : 'secondary'
          }
          data-testid="host-pressure-level"
        >
          {t(`sensors.pressure.level.${level}`)}
        </Badge>
        {level !== 'ok' && p.level_seconds > 0 && (
          <span className="text-xs text-muted-foreground">
            {t('sensors.pressure.since', undefined, {
              duration: formatDurationShort(p.level_seconds),
            })}
          </span>
        )}
        {reasons.map((r) => (
          <Badge key={r} variant="outline" className="font-normal">
            {t(`sensors.pressure.reason.${r}`)}
          </Badge>
        ))}
      </div>
      {p.noisy_neighbor && (
        <Alert data-testid="host-pressure-noisy">
          <TriangleAlert className="h-4 w-4" aria-hidden />
          <AlertDescription>{t('sensors.pressure.noisy')}</AlertDescription>
        </Alert>
      )}
      <DetailFieldGrid>
        <DetailField label={t('sensors.pressure.cpuStall')}>
          <span className="tabular-nums">{pct(p.cpu_some_avg10)}</span>
        </DetailField>
        {p.cpu_throttled_pct !== undefined && (
          <DetailField label={t('sensors.pressure.cpuThrottled')}>
            <span className="tabular-nums">{pct(p.cpu_throttled_pct)}</span>
          </DetailField>
        )}
        <DetailField label={t('sensors.pressure.memStall')}>
          <span className="tabular-nums">{pct(p.mem_some_avg10)}</span>
        </DetailField>
        <DetailField label={t('sensors.pressure.ioStall')}>
          <span className="tabular-nums">{pct(p.io_some_avg10)}</span>
        </DetailField>
        <DetailField label={t('sensors.pressure.loadPerCpu')}>
          <span className="tabular-nums">{p.load_per_cpu.toFixed(2)}</span>
        </DetailField>
        {cap && (
          <DetailField label={t('sensors.pressure.launchesHeld')}>
            <span className="tabular-nums">{cap.launches_held ?? 0}</span>
          </DetailField>
        )}
        {tr && (
          <DetailField label={t('sensors.pressure.retried')}>
            <span className="tabular-nums">
              {t('sensors.pressure.retriedValue', undefined, {
                retried: tr.retried,
                recovered: tr.recovered,
              })}
            </span>
          </DetailField>
        )}
      </DetailFieldGrid>
    </DetailSection>
  )
}
