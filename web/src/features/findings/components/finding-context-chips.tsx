'use client'

import { useMemo } from 'react'
import { Box, Boxes, FileCode, Layers, Radar, ShieldAlert, Tag, UserRound } from 'lucide-react'
import { ContextFilterChips, type ContextFilterChip } from '@/features/shared'
import { useAsset } from '@/features/assets/hooks/use-assets'
import { useComponentVersion } from '@/features/components/api/hooks'

/**
 * The Findings list's context filters (asset, scan run, CVE, rule, and the
 * drill-down filters of the other group dimensions: family, type, component,
 * owner), shown as inline toolbar chips with human labels.
 *
 * Asset names are resolved through the tenant- and permission-gated hook
 * (GET /assets/{id}); the API applies the caller's tenant and data scope, so
 * an id from another tenant or outside the caller's scope comes back 404 / 403
 * and the chip reads "Unknown asset": nothing about the record is shown. An id
 * that is not a UUID is never sent to the API at all (it is user-editable URL
 * input). The scan filter is the producer id findings carry (a scan run's
 * report or an import), shown as given, like the CVE and rule filters.
 */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export const UNKNOWN_ASSET_LABEL = 'Unknown asset'
export const UNKNOWN_COMPONENT_LABEL = 'Unknown component'

export interface FindingContextChipsProps {
  assetId?: string | null
  scanId?: string | null
  cveId?: string | null
  ruleId?: string | null
  family?: string | null
  findingType?: string | null
  componentId?: string | null
  /** The asset's primary owner (a user id; shown as an id, not resolved). */
  ownerId?: string | null
  /** The Unassigned owner group (`asset_owner_id_null=true`). */
  ownerUnassigned?: boolean
  /** Remove one URL parameter (its `param`); every other filter stays. */
  onRemove: (param: string) => void
  className?: string
}

/** True when any context filter is on, i.e. the chips will render. */
export function hasFindingContextFilters(p: Omit<FindingContextChipsProps, 'onRemove'>): boolean {
  return !!(
    p.assetId ||
    p.scanId ||
    p.cveId ||
    p.ruleId ||
    p.family ||
    p.findingType ||
    p.componentId ||
    p.ownerId ||
    p.ownerUnassigned
  )
}

export function FindingContextChips({
  assetId,
  scanId,
  cveId,
  ruleId,
  family,
  findingType,
  componentId,
  ownerId,
  ownerUnassigned,
  onRemove,
  className,
}: FindingContextChipsProps) {
  const validAssetId = assetId && UUID_RE.test(assetId) ? assetId : null
  const validComponentId = componentId && UUID_RE.test(componentId) ? componentId : null
  const { data: component, isLoading: componentLoading } = useComponentVersion(validComponentId)
  const componentName = (() => {
    const c = component as { name?: string; version?: string } | undefined
    const name = c?.name?.trim()
    return name ? [name, c?.version?.trim()].filter(Boolean).join(' ') : ''
  })()

  const { asset, isLoading: assetLoading } = useAsset(validAssetId)

  const assetName = asset?.name?.trim()

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
        mono: true,
        label: scanId,
      })
    }
    if (cveId) {
      out.push({ param: 'cve_id', kind: 'CVE', icon: ShieldAlert, mono: true, label: cveId })
    }
    if (ruleId) {
      out.push({ param: 'rule_id', kind: 'Rule', icon: FileCode, mono: true, label: ruleId })
    }
    if (family) {
      out.push({ param: 'family', kind: 'Family', icon: Layers, label: family })
    }
    if (findingType) {
      out.push({ param: 'finding_type', kind: 'Type', icon: Tag, label: findingType })
    }
    if (componentId) {
      out.push({
        param: 'component_id',
        kind: 'Component',
        icon: Boxes,
        fixedWidth: true,
        loading: !!validComponentId && componentLoading && !componentName,
        label: componentName || UNKNOWN_COMPONENT_LABEL,
      })
    }
    if (ownerUnassigned) {
      out.push({
        param: 'asset_owner_id_null',
        kind: 'Owner',
        icon: UserRound,
        label: 'Unassigned',
      })
    } else if (ownerId) {
      out.push({
        param: 'asset_owner_id',
        kind: 'Owner',
        icon: UserRound,
        mono: true,
        label: ownerId,
      })
    }
    return out
  }, [
    assetId,
    scanId,
    cveId,
    ruleId,
    family,
    findingType,
    componentId,
    ownerId,
    ownerUnassigned,
    validAssetId,
    validComponentId,
    assetLoading,
    componentLoading,
    assetName,
    componentName,
  ])

  return <ContextFilterChips chips={chips} onRemove={onRemove} className={className} />
}
