'use client'

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import type { Sensor } from '@/lib/api/sensor-types'

import { SensorHealthChip } from './sensor-health-dot'

export interface ZoneShare {
  zone_id: string
  zone_name: string
  targets: number
  jobs: number
  queued_jobs: number
  sensor_ids: string[]
}

/**
 * Each scan zone's share of a scan: targets, jobs (and how many wait for a
 * sensor) and the sensors the jobs go to. A handful of rows with no paging
 * or sorting, so a plain table rather than DataTable. Shared by the routing
 * preview and the run's Dispatch card.
 */
export function ZoneShareTable({
  zones,
  sensorsById,
  workflow,
}: {
  zones: ZoneShare[]
  sensorsById: Map<string, Sensor>
  /** Workflow steps are claimed by the zone's sensors, never pinned. */
  workflow?: boolean
}) {
  const { t } = useTranslation()
  return (
    <div className="overflow-x-auto rounded-md border" data-testid="zone-share-table">
      <table className="w-full text-sm">
        <caption className="sr-only">{t('scans.routing.zoneTableCaption')}</caption>
        <thead className="bg-muted/50 text-xs text-muted-foreground">
          <tr>
            <th className="px-3 py-2 text-start font-medium">{t('scans.routing.zone')}</th>
            <th className="px-3 py-2 text-end font-medium">{t('scans.routing.targets')}</th>
            <th className="px-3 py-2 text-end font-medium">{t('scans.routing.jobs')}</th>
            <th className="px-3 py-2 text-start font-medium">{t('scans.routing.sensors')}</th>
          </tr>
        </thead>
        <tbody className="divide-y">
          {zones.map((z) => (
            <tr key={z.zone_id}>
              <td className="px-3 py-2 font-medium">{z.zone_name}</td>
              <td className="px-3 py-2 text-end tabular-nums">{z.targets.toLocaleString()}</td>
              <td className="px-3 py-2 text-end tabular-nums">
                {z.jobs.toLocaleString()}
                {z.queued_jobs > 0 && (
                  <span className="block text-xs text-warning">
                    {t('scans.routing.waiting', undefined, { count: z.queued_jobs })}
                  </span>
                )}
              </td>
              <td className="px-3 py-2">
                <div className="flex flex-wrap gap-1">
                  {z.sensor_ids.length === 0 ? (
                    <span className="text-xs text-muted-foreground">
                      {workflow ? t('scans.routing.claimedByZone') : t('scans.routing.noSensorYet')}
                    </span>
                  ) : (
                    z.sensor_ids.map((id) => {
                      const s = sensorsById.get(id)
                      return s ? (
                        <SensorHealthChip key={id} sensor={s} />
                      ) : (
                        <Badge key={id} variant="outline" className="font-mono text-xs">
                          {id.slice(0, 8)}
                        </Badge>
                      )
                    })
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
