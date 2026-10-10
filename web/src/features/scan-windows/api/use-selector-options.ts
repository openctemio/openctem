/**
 * The objects a policy selector can name, from their existing list hooks:
 * asset groups, business units, scan zones, scope entries and programs.
 * Each list is read only when the caller holds its read permission (no
 * request otherwise); a selector id the caller cannot read shows as hidden.
 * The API checks every id against the organization when a policy is saved.
 */

'use client'

import { useMemo } from 'react'

import { useAssetGroupsApi } from '@/features/asset-groups/api/use-asset-groups-api'
import { useBusinessUnits } from '@/features/business-units/api/use-business-units'
import { usePrograms } from '@/features/programs/api/use-programs'
import { useScopeTargetsApi } from '@/features/scope/api/use-scope-api'
import type { MultiSelectOption } from '@/features/shared/components/multi-select'
import { useScanZones } from '@/lib/api/scan-zone-hooks'
import { Permission, usePermissions } from '@/lib/permissions'

import type { IdDimension, SelectorNames } from '../lib/selector'

export interface SelectorOptions {
  /** Options per id dimension (empty when the caller cannot read the list). */
  options: Record<IdDimension, MultiSelectOption[]>
  names: SelectorNames
  /** Whether the caller can read each list. */
  canRead: Record<IdDimension, boolean>
  loading: boolean
}

function toNames(opts: MultiSelectOption[]): Map<string, string> {
  return new Map(opts.map((o) => [o.value, o.label]))
}

export function useSelectorOptions(enabled = true): SelectorOptions {
  const { can } = usePermissions()
  const canRead: Record<IdDimension, boolean> = {
    asset_group_ids: enabled && can(Permission.AssetGroupsRead),
    business_unit_ids: enabled && can(Permission.AssetsRead),
    scan_zone_ids: enabled && can(Permission.ScanZonesRead),
    scope_target_ids: enabled && can(Permission.ScopeRead),
    program_ids: enabled && can(Permission.ProgramsRead),
  }
  // useAssetGroupsApi and usePrograms gate themselves on their permission.
  const groups = useAssetGroupsApi(
    { per_page: 100, sort_by: 'name' },
    { revalidateOnFocus: false, isPaused: () => !canRead.asset_group_ids }
  )
  const units = useBusinessUnits(undefined, canRead.business_unit_ids)
  const zones = useScanZones(canRead.scan_zone_ids)
  const scope = useScopeTargetsApi(
    { per_page: 100, sort_by: 'pattern', sort_order: 'asc' },
    { revalidateOnFocus: false, isPaused: () => !canRead.scope_target_ids }
  )
  const programs = usePrograms()

  const groupData = groups.data?.data
  const unitData = units.data?.data
  const zoneData = zones.data?.data
  const scopeData = scope.data?.data
  const programData = programs.data

  const options = useMemo<Record<IdDimension, MultiSelectOption[]>>(
    () => ({
      asset_group_ids: (groupData ?? []).map((g) => ({ value: g.id ?? '', label: g.name ?? '' })),
      business_unit_ids: (unitData ?? []).map((u) => ({ value: u.id, label: u.name })),
      scan_zone_ids: (zoneData ?? []).map((z) => ({ value: z.id, label: z.name })),
      scope_target_ids: (scopeData ?? []).map((s) => ({
        value: s.id ?? '',
        label: s.pattern ?? s.id ?? '',
      })),
      program_ids: canRead.program_ids
        ? (programData ?? []).map((p) => ({ value: p.id, label: p.name }))
        : [],
    }),
    [groupData, unitData, zoneData, scopeData, programData, canRead.program_ids]
  )
  const names = useMemo<SelectorNames>(
    () => ({
      asset_group_ids: toNames(options.asset_group_ids),
      business_unit_ids: toNames(options.business_unit_ids),
      scan_zone_ids: toNames(options.scan_zone_ids),
      scope_target_ids: toNames(options.scope_target_ids),
      program_ids: toNames(options.program_ids),
    }),
    [options]
  )
  return {
    options,
    names,
    canRead,
    loading: !!(
      groups.isLoading ||
      units.isLoading ||
      zones.isLoading ||
      scope.isLoading ||
      programs.isLoading
    ),
  }
}
