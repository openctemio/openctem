'use client'

import { HardDrive } from 'lucide-react'

import { HealthStatus } from '@/components/ui/health-status'
import { useTranslation } from '@/context/i18n-provider'
import { DetailField, DetailFieldGrid, DetailSection, RelativeTime } from '@/features/shared'
import type { Sensor } from '@/lib/api/sensor-types'
import type { HealthState } from '@/lib/health-colors'

import { formatBytes } from '../lib/format'
import { storeDiskLow, storeUsage } from '../lib/health-checks'

/** The local store section's id: the health callout links to it. */
export const SENSOR_LOCAL_STORE_SECTION_ID = 'sensor-local-store'

const CLASS_ORDER = [
  'workspace',
  'outbox',
  'dead_letter',
  'content_pack',
  'journal',
  'log',
  'state',
]

/**
 * The sensor's local data, as its latest heartbeats report it: whether it
 * still claims new jobs, how full the store and its disk are, what takes the
 * room and when it last cleaned up. Self-reported; the sensor decides to
 * stop claiming, the platform only shows it. Nothing when it reports none.
 */
export function SensorLocalStoreSection({ sensor }: { sensor: Pick<Sensor, 'local_store'> }) {
  const { t } = useTranslation()
  const store = sensor.local_store
  if (!store) return null
  const claiming: { state: HealthState; label: string } = store.stop_claiming
    ? { state: 'down', label: t('sensors.localStore.stopped', 'Stopped claiming new jobs') }
    : { state: 'ok', label: t('sensors.localStore.claiming', 'Claims new jobs') }
  const disk: { state: HealthState; label: string } | null =
    store.disk_level === 'critical'
      ? { state: 'down', label: t('sensors.localStore.disk.critical', 'Almost full') }
      : store.disk_level === 'low'
        ? { state: 'warn', label: t('sensors.localStore.disk.low', 'Low on space') }
        : store.disk_level === 'ok'
          ? { state: 'ok', label: t('sensors.localStore.disk.ok', 'Enough space') }
          : null
  const classes = Object.entries(store.bytes_by_class ?? {})
    .filter(([, b]) => b > 0)
    .sort(([a, x], [b, y]) => y - x || CLASS_ORDER.indexOf(a) - CLASS_ORDER.indexOf(b))
    .slice(0, 3)
  return (
    <DetailSection
      id={SENSOR_LOCAL_STORE_SECTION_ID}
      icon={HardDrive}
      title={t('sensors.localStore.title', 'Local storage')}
    >
      <DetailFieldGrid>
        <DetailField label={t('sensors.localStore.jobs', 'New jobs')}>
          <HealthStatus state={claiming.state} label={claiming.label} />
        </DetailField>
        <DetailField label={t('sensors.localStore.store', 'Store')}>
          <span className="tabular-nums">{storeUsage(store, t)}</span>
        </DetailField>
        {disk && (
          <DetailField label={t('sensors.localStore.diskLabel', 'Disk')}>
            <HealthStatus state={disk.state} label={disk.label} />
          </DetailField>
        )}
        {classes.length > 0 && (
          <DetailField label={t('sensors.localStore.largest', 'Largest')}>
            <span className="flex flex-col tabular-nums">
              {classes.map(([c, b]) => (
                <span key={c}>
                  {t(`sensors.localStore.class.${c}`, c)}: {formatBytes(b)}
                </span>
              ))}
            </span>
          </DetailField>
        )}
        {store.last_sweep_at && (
          <DetailField label={t('sensors.localStore.cleaned', 'Last cleanup')}>
            <RelativeTime date={store.last_sweep_at} className="text-foreground" />
          </DetailField>
        )}
      </DetailFieldGrid>
      {store.stop_claiming && (
        <p className="text-xs text-muted-foreground">
          {storeDiskLow(store)
            ? t(
                'sensors.localStore.fixDisk',
                'Free disk space on the sensor host. The sensor resumes claiming on its own; results it already holds keep uploading.'
              )
            : t(
                'sensors.localStore.fixStore',
                'Free disk space on the sensor host or raise its store quota. The sensor resumes claiming on its own; results it already holds keep uploading.'
              )}
        </p>
      )}
    </DetailSection>
  )
}
