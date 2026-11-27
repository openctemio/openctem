'use client'

/**
 * Scanner picker for single-scanner scans: the tool registry's active
 * scanners, the same list the API checks a scan's scanner_name against
 * (it refuses unknown, disabled and collector tools). A scanner no online
 * sensor may run stays selectable with the reason (api
 * tool-availability.md): the scan is saved, and its start is refused with
 * NO_SENSOR_FOR_TOOL until such a sensor is online.
 */

import { useMemo } from 'react'
import { useTranslation } from '@/context/i18n-provider'

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useToolAvailability, useTools } from '@/lib/api/tool-hooks'
import type { Tool, ToolAvailabilityItem } from '@/lib/api/tool-types'
import { availabilityByName, toolUnavailableReason } from '@/features/tools/lib/availability'
import type { ScanIntensity } from '@/lib/api/scan-types'
import { fitsIntensity, toolTier } from '../lib/scan-intensity'

/**
 * Tools a scan may name: active and not an asset collector. A connector (the
 * Tenable.sc sensor connector) only when the caller can collect its
 * scanner_config (the New/Edit scan wizard, while the connector is enabled).
 * Sorted by label.
 */
export function scannerOptions(tools: Tool[] | undefined, allowConnectors = false): Tool[] {
  return (tools ?? [])
    .filter(
      (t) =>
        t.is_active &&
        t.metadata?.kind !== 'collector' &&
        (allowConnectors || t.metadata?.kind !== 'connector')
    )
    .sort((a, b) => (a.display_name || a.name).localeCompare(b.display_name || b.name))
}

/**
 * Why a scanner cannot be picked now, or null. Connectors run through their
 * integration, not a sensor's manifest, so availability does not apply to
 * them; unknown availability (still loading, or unreadable) never blocks.
 */
export function scannerUnavailableReason(
  tool: Tool,
  availability: Map<string, ToolAvailabilityItem> | null,
  t: Parameters<typeof toolUnavailableReason>[1],
  inZone = false
): string | null {
  if (!availability || tool.metadata?.kind === 'connector') return null
  return toolUnavailableReason(availability.get(tool.name), t, inZone)
}

export function useScannerOptions(allowConnectors = false, zoneId?: string | null) {
  const { data, isLoading, error } = useTools({ per_page: 100 }, { revalidateOnFocus: false })
  const { data: avail } = useToolAvailability(zoneId, { revalidateOnFocus: false })
  const options = useMemo(
    () => scannerOptions(data?.items, allowConnectors),
    [data?.items, allowConnectors]
  )
  const availability = useMemo(() => (avail ? availabilityByName(avail.items) : null), [avail])
  return { options, availability, isLoading, error }
}

interface ScannerSelectProps {
  id?: string
  /** Help and error ids of the field around it. */
  'aria-describedby'?: string
  'aria-invalid'?: true
  'aria-required'?: true
  value: string
  onChange: (name: string) => void
  disabled?: boolean
  /** Offer connector scanners (see scannerOptions). */
  allowConnectors?: boolean
  /** The scan's zone: availability is judged on that zone's sensors. */
  zoneId?: string | null
  /**
   * The scan's intensity (RFC-071): only scanners that probe within it are
   * offered (the API refuses the others).
   */
  intensity?: ScanIntensity
}

export function ScannerSelect({
  id,
  value,
  onChange,
  disabled,
  allowConnectors = false,
  'aria-describedby': describedBy,
  'aria-invalid': invalid,
  'aria-required': required,
  zoneId,
  intensity,
}: ScannerSelectProps) {
  const { t } = useTranslation()
  const {
    options: allOptions,
    availability,
    isLoading,
    error,
  } = useScannerOptions(allowConnectors, zoneId)
  const options = useMemo(
    () =>
      intensity
        ? allOptions.filter((tool) => fitsIntensity(toolTier(tool.name), intensity))
        : allOptions,
    [allOptions, intensity]
  )
  // Keep a configuration's scanner selectable even if the registry no longer
  // lists it (disabled since), so opening Edit does not silently blank it.
  const known = options.some((tool) => tool.name === value)
  const selected = options.find((tool) => tool.name === value)
  const selectedReason = selected
    ? scannerUnavailableReason(selected, availability, t, !!zoneId)
    : null

  const placeholder = isLoading
    ? t('scans.scanner.loading')
    : error
      ? t('scans.scanner.loadFailed')
      : options.length === 0
        ? t('scans.scanner.none')
        : t('scans.scanner.choose')

  return (
    <div className="space-y-1">
      <Select value={value || undefined} onValueChange={onChange} disabled={disabled}>
        <SelectTrigger
          id={id}
          className="w-full"
          aria-label={t('scans.basic.scanner')}
          aria-describedby={describedBy}
          aria-invalid={invalid}
          aria-required={required}
        >
          {/* The field shows the scanner's name only; the reason a sensor
              cannot run it is in the list and in the note below the field. */}
          <SelectValue placeholder={placeholder}>
            {selected ? selected.display_name || selected.name : undefined}
          </SelectValue>
        </SelectTrigger>
        <SelectContent>
          {value && !known && (
            <SelectItem value={value}>
              {t('scans.scanner.notActive', undefined, { name: value })}
            </SelectItem>
          )}
          {options.map((tool) => {
            // A scanner no sensor can run now stays selectable with why: the
            // scan is saved, and only its start waits for such a sensor.
            const reason = scannerUnavailableReason(tool, availability, t, !!zoneId)
            return (
              <SelectItem key={tool.id} value={tool.name} title={reason ?? undefined}>
                <span className="flex flex-col">
                  <span>{tool.display_name || tool.name}</span>
                  {reason && <span className="text-xs text-muted-foreground">{reason}</span>}
                </span>
              </SelectItem>
            )
          })}
        </SelectContent>
      </Select>
      {selectedReason && (
        <p className="text-xs text-warning" role="status">
          {t('scans.scanner.refusedUntil', undefined, { reason: selectedReason })}
        </p>
      )}
    </div>
  )
}
