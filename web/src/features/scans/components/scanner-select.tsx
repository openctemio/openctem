'use client'

/**
 * Scanner picker for single-scanner scans: the tool registry's active
 * scanners, the same list the API checks a scan's scanner_name against
 * (it refuses unknown, disabled and collector tools). Replaces the hardcoded
 * "nuclei" (New/Edit scan) and the fixed four-item list (Quick scan), which
 * offered tools no sensor ships.
 */

import { useMemo } from 'react'

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useTools } from '@/lib/api/tool-hooks'
import type { Tool } from '@/lib/api/tool-types'

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

export function useScannerOptions(allowConnectors = false) {
  const { data, isLoading, error } = useTools(
    { is_active: true, per_page: 100 },
    { revalidateOnFocus: false }
  )
  const options = useMemo(
    () => scannerOptions(data?.items, allowConnectors),
    [data?.items, allowConnectors]
  )
  return { options, isLoading, error }
}

interface ScannerSelectProps {
  id?: string
  value: string
  onChange: (name: string) => void
  disabled?: boolean
  /** Offer connector scanners (see scannerOptions). */
  allowConnectors?: boolean
}

export function ScannerSelect({
  id,
  value,
  onChange,
  disabled,
  allowConnectors = false,
}: ScannerSelectProps) {
  const { options, isLoading, error } = useScannerOptions(allowConnectors)
  // Keep a configuration's scanner selectable even if the registry no longer
  // lists it (disabled since), so opening Edit does not silently blank it.
  const known = options.some((t) => t.name === value)

  const placeholder = isLoading
    ? 'Loading scanners…'
    : error
      ? 'Could not load scanners'
      : options.length === 0
        ? 'No active scanners'
        : 'Choose a scanner'

  return (
    <Select value={value || undefined} onValueChange={onChange} disabled={disabled}>
      <SelectTrigger id={id} aria-label="Scanner">
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        {value && !known && (
          <SelectItem value={value}>{value} (not active in the tool registry)</SelectItem>
        )}
        {options.map((t) => (
          <SelectItem key={t.id} value={t.name}>
            {t.display_name || t.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}
