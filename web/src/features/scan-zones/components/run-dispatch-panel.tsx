'use client'

import { AlertTriangle } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { useTranslation } from '@/context/i18n-provider'
import type { RunDispatch } from '@/lib/api/scan-types'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import { Permission, useHasPermission } from '@/lib/permissions'

import { ExcludedTargetsList } from '@/features/scans/components/excluded-targets-list'
import { TargetOutcomes } from '@/features/scans/components/target-outcomes'
import {
  groupsFromUncovered,
  isSkipWarning,
  type SkipGroup,
} from '@/features/scans/lib/skip-groups'

import { useZoneSensors } from '../hooks/use-zone-sensors'
import { ZoneShareTable } from './zone-share-table'

/** The skip groups of a run, or, for a run recorded before them, groups made from the listed uncovered targets. */
function runSkipGroups(dispatch: RunDispatch): { willScan: number; groups: SkipGroup[] } {
  const routing = dispatch.zone_routing
  if (dispatch.skipped) {
    return {
      willScan: dispatch.will_scan ?? dispatch.resolved_targets,
      groups: dispatch.skipped,
    }
  }
  const uncovered = routing?.uncovered_targets ?? dispatch.uncovered_targets?.length ?? 0
  const groups = groupsFromUncovered(dispatch.uncovered_targets ?? [], uncovered)
  if (dispatch.excluded_targets > 0) {
    groups.push({
      reason: 'excluded',
      tone: 'info',
      count: dispatch.excluded_targets,
      targets: (dispatch.excluded ?? []).map((e) => e.target ?? '').filter(Boolean),
    })
    groups.sort((a, b) => b.count - a.count)
  }
  return { willScan: Math.max(dispatch.resolved_targets - uncovered, 0), groups }
}

/**
 * What a scan run dispatched (GET /scan-runs/{id} `dispatch`): how many
 * targets it scanned, every skipped target grouped by reason (never dropped
 * silently, never shown as a failure), the zone each share went to when the
 * team has zones, and what each dynamic target held at the start.
 */
export function RunDispatchPanel({ dispatch }: { dispatch: RunDispatch }) {
  const { t } = useTranslation()
  const canReadSensors = useHasPermission(Permission.SensorsRead)
  const canReadZones = useHasPermission(Permission.ScanZonesRead)
  const { byId: sensorsById } = useZoneSensors(canReadSensors)
  const { data: zonesData } = useScanZones(canReadZones && !!dispatch.zone_routing)
  const routing = dispatch.zone_routing
  const selectedZoneId = routing?.selected_zone_id ?? routing?.zone_id
  const selectedZoneName =
    selectedZoneId &&
    (routing?.zones?.find((z) => z.zone_id === selectedZoneId)?.zone_name ??
      zonesData?.data.find((z) => z.id === selectedZoneId)?.name ??
      t('scans.dispatch.zoneGone'))
  const { willScan, groups } = runSkipGroups(dispatch)
  const warnings = (dispatch.warnings ?? []).filter((w) => !isSkipWarning(w))
  const zonesUsed = !!routing?.zones && routing.zones.length > 0

  return (
    <div className="space-y-4" data-testid="run-dispatch">
      <TargetOutcomes
        willScan={willScan}
        groups={groups}
        variant="run"
        detail={
          (dispatch.excluded?.length ?? 0) > 0
            ? {
                excluded: (
                  <ExcludedTargetsList
                    items={dispatch.excluded ?? []}
                    total={dispatch.excluded_targets}
                  />
                ),
              }
            : undefined
        }
      />

      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        {dispatch.sensor_routing && (
          <Badge variant="outline" className="font-normal">
            {dispatch.sensor_routing === 'platform'
              ? t('scans.sensorPref.platform.label')
              : t('scans.sensorPref.tenant.label')}
          </Badge>
        )}
        {routing && (routing.jobs ?? 0) > 0 && (
          <Badge variant="outline" className="font-normal">
            {t('scans.dispatch.jobs', undefined, { count: routing.jobs ?? 0 })}
          </Badge>
        )}
        {routing?.selected_zone_id && (
          <Badge variant="outline" className="font-normal">
            {t('scans.dispatch.restrictedToZone', undefined, { name: selectedZoneName || '' })}
          </Badge>
        )}
        {!routing?.selected_zone_id && routing?.zone_id && (
          <Badge variant="outline" className="font-normal">
            {t('scans.dispatch.workflowZone', undefined, { name: selectedZoneName || '' })}
          </Badge>
        )}
        {zonesUsed && routing && routing.unzoned_targets > 0 && (
          <span>{t('scans.routing.unzoned', undefined, { count: routing.unzoned_targets })}</span>
        )}
      </div>

      {dispatch.target_expansion && dispatch.target_expansion.length > 0 && (
        <section aria-labelledby="run-expansion-heading" className="space-y-2">
          <h4 id="run-expansion-heading" className="text-sm font-semibold">
            {t('scans.dispatch.resolvedAtStart')}
          </h4>
          <p className="text-xs text-muted-foreground">{t('scans.dispatch.resolvedAtStartHelp')}</p>
          <ul className="divide-y rounded-md border" data-testid="run-target-expansion">
            {dispatch.target_expansion.map((e) => (
              <li key={`${e.kind}:${e.selector}`} className="space-y-0.5 px-3 py-2">
                <p className="flex flex-wrap items-center gap-2">
                  <span className="break-all font-mono text-sm">{e.selector}</span>
                  <span className="text-xs text-muted-foreground">
                    {e.kind === 'cidr'
                      ? t('scans.dispatch.knownHosts', undefined, { count: e.matched })
                      : t('scans.dispatch.knownNames', undefined, { count: e.matched })}
                  </span>
                  {e.capped && (
                    <Badge variant="outline" className="border-warning/50 font-normal text-warning">
                      {t('scans.dispatch.capped')}
                    </Badge>
                  )}
                </p>
                {e.sample && e.sample.length > 0 && (
                  <p className="truncate text-xs text-muted-foreground">{e.sample.join(', ')}</p>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      {zonesUsed && routing?.zones && (
        <ZoneShareTable
          zones={routing.zones}
          sensorsById={sensorsById}
          workflow={!!routing.zone_id}
        />
      )}

      {warnings.length > 0 && (
        <section aria-labelledby="run-warnings-heading" className="space-y-2">
          <h4 id="run-warnings-heading" className="flex items-center gap-2 text-sm font-semibold">
            <AlertTriangle className="h-4 w-4 text-warning" aria-hidden />
            {t('scans.dispatch.warnings')}
          </h4>
          <ul className="list-disc space-y-1 ps-5 text-sm" data-testid="run-warnings">
            {warnings.map((w, i) => (
              <li key={i} className="break-words">
                {w}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  )
}
