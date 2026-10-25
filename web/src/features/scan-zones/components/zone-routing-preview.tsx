'use client'

import { useEffect, useMemo, useState } from 'react'
import useSWR from 'swr'
import { AlertCircle, AlertTriangle, Info } from 'lucide-react'

import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { SCAN_WINDOW_NEVER_OPENS, WindowWaits } from '@/features/scan-windows'
import { TargetOutcomes } from '@/features/scans/components/target-outcomes'
import { isSkipWarning, type SkipGroup } from '@/features/scans/lib/skip-groups'
import { previewScanZoneRouting } from '@/lib/api/scan-zone-hooks'
import type { ScanZone, ScanZonePreview, ScanZonePreviewRequest } from '@/lib/api/scan-zone-types'
import { Permission, useHasPermission } from '@/lib/permissions'

import { useZoneSensors } from '../hooks/use-zone-sensors'
import { describeScanZoneError, scanZoneErrorHint } from '../lib/errors'
import { ZoneShareTable } from './zone-share-table'

const AUTOMATIC = 'automatic'

interface ScanZonePickerProps {
  zones: ScanZone[]
  value: string | null | undefined
  onChange: (zoneId: string | null) => void
  id?: string
}

/** "Automatic" (the default: narrowest zone per target) or one zone. */
export function ScanZonePicker({ zones, value, onChange, id = 'scan-zone' }: ScanZonePickerProps) {
  const { t } = useTranslation()
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{t('scans.routing.zonePicker')}</Label>
      <Select
        value={value ?? AUTOMATIC}
        onValueChange={(v) => onChange(v === AUTOMATIC ? null : v)}
      >
        <SelectTrigger id={id} className="w-full sm:w-80">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value={AUTOMATIC}>{t('scans.routing.automatic')}</SelectItem>
          {zones.map((z) => (
            <SelectItem key={z.id} value={z.id}>
              {z.is_default ? t('scans.routing.defaultZone', undefined, { name: z.name }) : z.name}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p className="text-xs text-muted-foreground">
        {value ? t('scans.routing.pinnedHelp') : t('scans.routing.automaticHelp')}
      </p>
    </div>
  )
}

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return v
}

/**
 * The skip groups of a preview. An API older than the groups sends only the
 * per-target rows: they are grouped here by status (excluded rows are not
 * listed there, only counted).
 */
export function previewSkipGroups(data: ScanZonePreview): {
  willScan: number
  groups: SkipGroup[]
} {
  if (data.skipped) {
    return { willScan: data.will_scan ?? 0, groups: data.skipped }
  }
  const uncovered = data.targets.filter((r) => r.status === 'uncovered')
  const byKind = new Map<string, SkipGroup>()
  for (const r of uncovered) {
    const reason = r.kind ?? 'other'
    const g = byKind.get(reason) ?? {
      reason,
      tone: reason === 'unresolved' ? 'info' : 'warning',
      count: 0,
      targets: [],
    }
    g.count++
    g.targets.push(r.target)
    byKind.set(reason, g)
  }
  if (data.excluded_targets > 0) {
    byKind.set('excluded', {
      reason: 'excluded',
      tone: 'info',
      count: data.excluded_targets,
      targets: data.excluded,
    })
  }
  const groups = [...byKind.values()].sort((a, b) => b.count - a.count)
  return { willScan: Math.max(data.resolved_targets - (data.uncovered_targets ?? 0), 0), groups }
}

interface ZoneRoutingPreviewProps {
  request: ScanZonePreviewRequest
  /** Typed targets the user may take out of the scan from the review. */
  removable?: (target: string) => boolean
  onRemove?: (targets: string[]) => void
}

/**
 * What a scan would do if it started now, computed by the API with the
 * trigger's own code (read-only): how many targets it scans, every skipped
 * target grouped by reason, and, when the team has scan zones and targets
 * go to them, each zone's share. Teams without zones see no zone wording.
 */
export function ZoneRoutingPreview({ request, removable, onRemove }: ZoneRoutingPreviewProps) {
  const { t } = useTranslation()
  const canRead = useHasPermission(Permission.ScanZonesRead)
  const canReadSensors = useHasPermission(Permission.SensorsRead)
  const { byId: sensorsById } = useZoneSensors(canReadSensors)
  const debounced = useDebounced(request, 400)
  const key = useMemo(
    () =>
      canRead && (debounced.targets.length > 0 || debounced.asset_group_ids.length > 0)
        ? ['scan-zone-preview', JSON.stringify(debounced)]
        : null,
    [canRead, debounced]
  )
  const { data, error, isLoading } = useSWR(key, () => previewScanZoneRouting(debounced), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  })

  if (!canRead) return null
  if (!key) {
    return <p className="text-sm text-muted-foreground">{t('scans.targetOutcome.addTargets')}</p>
  }
  if (isLoading || !data) {
    if (error) {
      const d = describeScanZoneError(error, t('scans.targetOutcome.previewFailed'))
      return (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>{t('scans.targetOutcome.previewFailed')}</AlertTitle>
          <AlertDescription>{d.message}</AlertDescription>
        </Alert>
      )
    }
    return (
      <div className="space-y-2" aria-busy="true">
        <Skeleton className="h-5 w-1/2" />
        <Skeleton className="h-16 w-full" />
      </div>
    )
  }

  const { willScan, groups } = previewSkipGroups(data)
  const zonesUsed = data.zones_enabled && data.zones.length > 0
  const warnings = data.warnings.filter((w) => !isSkipWarning(w))

  return (
    <div className="space-y-3" data-testid="zone-routing-preview">
      {data.windows && (
        <WindowWaits
          waitingCount={data.windows.waiting_count}
          waiting={data.windows.waiting}
          nextOpenAt={data.windows.next_open_at}
          neverCount={data.windows.never_count}
          never={data.windows.never}
        />
      )}

      {data.error && !(data.windows && data.error.code === SCAN_WINDOW_NEVER_OPENS) && (
        <Alert variant="destructive" data-testid="zone-preview-refusal">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>{t('scans.targetOutcome.wouldNotStart')}</AlertTitle>
          <AlertDescription>
            <p>{data.error.message}</p>
            {scanZoneErrorHint(data.error.code) && <p>{scanZoneErrorHint(data.error.code)}</p>}
          </AlertDescription>
        </Alert>
      )}

      <TargetOutcomes
        willScan={willScan}
        groups={groups}
        removable={removable}
        onRemove={onRemove}
      />

      {data.zones_enabled && !data.routed && (
        <p className="flex items-start gap-2 text-sm text-muted-foreground">
          <Info className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          {t('scans.routing.notRouted')}
        </p>
      )}

      {zonesUsed && (
        <div className="space-y-2">
          <ZoneShareTable
            zones={data.zones}
            sensorsById={sensorsById}
            workflow={request.scan_type === 'workflow'}
          />
          {data.unzoned_targets > 0 && (
            <p className="text-xs text-muted-foreground">
              {t('scans.routing.unzoned', undefined, { count: data.unzoned_targets })}
            </p>
          )}
        </div>
      )}

      {warnings.length > 0 && (
        <ul className="space-y-1 text-xs text-muted-foreground">
          {warnings.map((w, i) => (
            <li key={i} className="flex items-start gap-1.5">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" aria-hidden />
              <span className="break-words">{w}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

interface ScanRoutingSectionProps {
  /** The team's scan zones; none: no zone picker and no zone wording. */
  zones: ScanZone[]
  value: string | null | undefined
  onChange: (zoneId: string | null) => void
  request: ScanZonePreviewRequest
  removable?: (target: string) => boolean
  onRemove?: (targets: string[]) => void
}

/**
 * The New / Edit scan block "What this scan covers": the zone picker (only
 * when the team has zones) and the live preview of what Start would do.
 */
export function ScanRoutingSection({
  zones,
  value,
  onChange,
  request,
  removable,
  onRemove,
}: ScanRoutingSectionProps) {
  const { t } = useTranslation()
  return (
    <section
      aria-labelledby="scan-routing-heading"
      className="space-y-4 border-t px-4 py-4 sm:px-6"
      data-testid="new-scan-routing"
    >
      <div>
        <h3 id="scan-routing-heading" className="text-sm font-semibold">
          {t('scans.targetOutcome.title')}
        </h3>
        <p className="text-xs text-muted-foreground">{t('scans.targetOutcome.subtitle')}</p>
      </div>
      {zones.length > 0 && <ScanZonePicker zones={zones} value={value} onChange={onChange} />}
      <ZoneRoutingPreview request={request} removable={removable} onRemove={onRemove} />
    </section>
  )
}
