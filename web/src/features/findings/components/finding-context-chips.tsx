'use client'

import { useMemo } from 'react'
import { Box, FileCode, Radar, ShieldAlert } from 'lucide-react'
import { ContextFilterChips, type ContextFilterChip } from '@/features/shared'
import { useAsset } from '@/features/assets/hooks/use-assets'
import { useScanSession } from '@/lib/api/scan-hooks'

/**
 * The Findings list's context filters (asset, scan run, CVE, rule), shown as
 * inline toolbar chips with human labels.
 *
 * Asset and scan names are resolved through the existing tenant- and
 * permission-gated hooks (GET /assets/{id}, GET /scan-sessions/{id}); the API
 * applies the caller's tenant and data scope, so an id from another tenant or
 * outside the caller's scope comes back 404 / 403 and the chip reads "Unknown
 * asset" / "Unknown scan" — nothing about the record is shown. An id that is
 * not a UUID is never sent to the API at all (it is user-editable URL input).
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export const UNKNOWN_ASSET_LABEL = 'Unknown asset'
export const UNKNOWN_SCAN_LABEL = 'Unknown scan'

export interface FindingContextChipsProps {
  assetId?: string | null
  scanId?: string | null
  cveId?: string | null
  ruleId?: string | null
  /** Remove one URL parameter (`asset_id`, `scan_id`, `cve_id`, `rule_id`). */
  onRemove: (param: string) => void
  className?: string
}

/** True when any context filter is on, i.e. the chips will render. */
export function hasFindingContextFilters(p: Omit<FindingContextChipsProps, 'onRemove'>): boolean {
  return !!(p.assetId || p.scanId || p.cveId || p.ruleId)
}

export function FindingContextChips({
  assetId,
  scanId,
  cveId,
  ruleId,
  onRemove,
  className,
}: FindingContextChipsProps) {
  const validAssetId = assetId && UUID_RE.test(assetId) ? assetId : null
  const validScanId = scanId && UUID_RE.test(scanId) ? scanId : null

  const { asset, isLoading: assetLoading } = useAsset(validAssetId)
  const { data: session, isLoading: sessionLoading } = useScanSession(validScanId)

  const assetName = asset?.name?.trim()
  const scanName = session
    ? [session.scanner_name, session.asset_value].filter((v) => v && v.trim()).join(' · ')
    : ''

  const chips = useMemo<ContextFilterChip[]>(() => {
    const out: ContextFilterChip[] = []
    if (assetId) {
      out.push({
        param: 'asset_id',
        kind: 'Asset',
        icon: Box,
        fixedWidth: true,
        loading: !!validAssetId && assetLoading && !assetName,
        label: assetName || UNKNOWN_ASSET_LABEL,
      })
    }
    if (scanId) {
      out.push({
        param: 'scan_id',
        kind: 'Scan',
        icon: Radar,
        fixedWidth: true,
        loading: !!validScanId && sessionLoading && !scanName,
        label: scanName || UNKNOWN_SCAN_LABEL,
      })
    }
    if (cveId) {
      out.push({ param: 'cve_id', kind: 'CVE', icon: ShieldAlert, mono: true, label: cveId })
    }
    if (ruleId) {
      out.push({ param: 'rule_id', kind: 'Rule', icon: FileCode, mono: true, label: ruleId })
    }
    return out
  }, [
    assetId,
    scanId,
    cveId,
    ruleId,
    validAssetId,
    validScanId,
    assetLoading,
    sessionLoading,
    assetName,
    scanName,
  ])

  return <ContextFilterChips chips={chips} onRemove={onRemove} className={className} />
}
